//! MCP Gateway plugin.
//!
//! Makes HTTP-based Model Context Protocol JSON-RPC traffic visible to Ferrum:
//! it extracts `mcp.*` metadata, preserves MCP session headers, aggregates
//! discovery catalogs in aggregate-router mode, and routes namespaced MCP tool,
//! resource, and prompt calls to configured upstream MCP servers.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use url::Url;

use crate::config::types::BackendScheme;

use super::{HTTP_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext};

const DEFAULT_PROTOCOL_VERSION: &str = "2025-11-25";
const METADATA_REWRITE_KEY: &str = "mcp.needs_request_rewrite";

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
    #[allow(dead_code)] // Parsed for V1 config compatibility; result validation is a V2 path.
    validate_tool_results: bool,
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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
struct McpCatalog {
    tools: HashMap<String, ToolCatalogEntry>,
    prompts: HashMap<String, PromptCatalogEntry>,
    resources: HashMap<String, ResourceCatalogEntry>,
    version: u64,
    last_refreshed_at: Option<Instant>,
    last_refreshed_wall: DateTime<Utc>,
}

impl Default for McpCatalog {
    fn default() -> Self {
        Self {
            tools: HashMap::new(),
            prompts: HashMap::new(),
            resources: HashMap::new(),
            version: 0,
            last_refreshed_at: None,
            last_refreshed_wall: Utc::now(),
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
}

#[derive(Debug, Clone)]
struct DownstreamMcpSession {
    #[allow(dead_code)] // Useful in snapshots/debug views; map key is used for lookup.
    downstream_session_id: String,
    protocol_version: String,
    client_info: Option<Value>,
    client_capabilities: Option<Value>,
    upstream_sessions: HashMap<String, UpstreamMcpSession>,
}

#[derive(Debug, Clone)]
struct UpstreamMcpSession {
    #[allow(dead_code)] // Useful in snapshots/debug views; map key is used for lookup.
    server_id: String,
    upstream_session_id: Option<String>,
    initialized: bool,
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
    catalog: Arc<RwLock<McpCatalog>>,
    session_store: Arc<DashMap<String, DownstreamMcpSession>>,
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
        let mode =
            McpGatewayMode::parse(optional_string(object, "mode")?.unwrap_or("transparent_proxy"))?;

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
        let enabled_server_ids: Vec<&str> = servers
            .values()
            .filter(|server| server.enabled)
            .map(|server| server.server_id.as_str())
            .collect();
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

        let primary_server_id = enabled_server_ids
            .first()
            .ok_or_else(|| "mcp_gateway: at least one server must be enabled".to_string())?
            .to_string();

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
            catalog: Arc::new(RwLock::new(McpCatalog::default())),
            session_store: Arc::new(DashMap::new()),
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

    fn downstream_session_id_from_headers(
        &self,
        headers: &HashMap<String, String>,
    ) -> Option<String> {
        header_value(headers, &self.sessions.downstream_session_header).map(ToOwned::to_owned)
    }

    fn upstream_session_id(&self, downstream_id: &str, server_id: &str) -> Option<String> {
        self.session_store.get(downstream_id).and_then(|session| {
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
        ctx.route_override_path = Some(server.target.path.clone());
        ctx.route_override_authority = Some(server.target.authority.clone());
        headers.insert("host".to_string(), server.target.authority.clone());
        if let Some(downstream_id) = downstream_session_id
            && let Some(upstream_id) = self.upstream_session_id(downstream_id, &server.server_id)
        {
            headers.insert(
                self.sessions.upstream_session_header.to_ascii_lowercase(),
                upstream_id,
            );
        }
        if self.observability.emit_metadata {
            ctx.metadata
                .insert("mcp.server_id".to_string(), server.server_id.clone());
            ctx.metadata
                .insert("mcp.route_decision".to_string(), "forward".to_string());
        }
    }

    fn primary_server(&self) -> Option<&McpServerConfig> {
        self.servers.get(&self.primary_server_id)
    }

    fn create_downstream_session(
        &self,
        protocol_version: String,
        client_info: Option<Value>,
        client_capabilities: Option<Value>,
    ) -> String {
        let downstream_session_id = uuid::Uuid::new_v4().to_string();
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
                        initialized: false,
                    },
                )
            })
            .collect();
        self.session_store.insert(
            downstream_session_id.clone(),
            DownstreamMcpSession {
                downstream_session_id: downstream_session_id.clone(),
                protocol_version,
                client_info,
                client_capabilities,
                upstream_sessions,
            },
        );
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
        if self
            .session_store
            .get(downstream_session_id)
            .and_then(|session| {
                session
                    .upstream_sessions
                    .get(server_id)
                    .filter(|upstream| upstream.initialized)
                    .map(|upstream| upstream.upstream_session_id.clone())
            })
            .is_some()
        {
            return Ok(self.upstream_session_id(downstream_session_id, server_id));
        }

        let session = self
            .session_store
            .get(downstream_session_id)
            .map(|session| session.clone())
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
            .header("accept", "application/json")
            .header(
                "mcp-protocol-version",
                self.protocol_version_for_session(downstream_session_id),
            )
            .json(&body);
        let response = self
            .http_client
            .execute_tracked(request, "mcp_gateway.initialize", &ctx.plugin_http_call_ns)
            .await
            .map_err(|error| format!("failed to initialize upstream MCP server: {error}"))?;
        if !response.status().is_success() {
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

        if let Some(mut session) = self.session_store.get_mut(downstream_session_id)
            && let Some(upstream) = session.upstream_sessions.get_mut(server_id)
        {
            upstream.initialized = true;
            upstream.upstream_session_id = upstream_session_id.clone();
        }
        Ok(upstream_session_id)
    }

    fn protocol_version_for_session(&self, downstream_session_id: &str) -> String {
        self.session_store
            .get(downstream_session_id)
            .map(|session| session.protocol_version.clone())
            .unwrap_or_else(|| self.supported_protocol_versions[0].clone())
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
            .header("accept", "application/json")
            .header(
                "mcp-protocol-version",
                self.protocol_version_for_session(downstream_session_id),
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
            .map_err(|error| format!("upstream MCP request failed: {error}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "upstream MCP request returned HTTP {}",
                response.status()
            ));
        }
        response
            .json::<Value>()
            .await
            .map_err(|error| format!("upstream MCP response was not JSON: {error}"))
    }

    async fn ensure_catalog(
        &self,
        ctx: &RequestContext,
        downstream_session_id: &str,
    ) -> Result<(), String> {
        {
            let catalog = self.catalog.read().await;
            if !catalog.is_stale(self.discovery.cache_ttl) {
                return Ok(());
            }
        }
        self.refresh_catalog(ctx, downstream_session_id).await
    }

    async fn refresh_catalog(
        &self,
        ctx: &RequestContext,
        downstream_session_id: &str,
    ) -> Result<(), String> {
        let old_catalog = self.catalog.read().await.clone();
        let mut tools = HashMap::new();
        let mut prompts = HashMap::new();
        let mut resources = HashMap::new();
        let discovered_at = Utc::now();

        for server in self.servers.values().filter(|server| server.enabled) {
            if self.discovery.aggregate_tools && server.expose_tools {
                let response = self
                    .request_upstream_json(
                        ctx,
                        downstream_session_id,
                        server,
                        "tools/list",
                        json!({}),
                    )
                    .await?;
                let items = response
                    .get("result")
                    .and_then(|result| result.get("tools"))
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for item in items {
                    if let Some(entry) =
                        self.tool_entry_from_value(server, item, discovered_at, &old_catalog)
                    {
                        tools.insert(entry.public_name.clone(), entry);
                    }
                }
            }
            if self.discovery.aggregate_prompts && server.expose_prompts {
                let response = self
                    .request_upstream_json(
                        ctx,
                        downstream_session_id,
                        server,
                        "prompts/list",
                        json!({}),
                    )
                    .await?;
                let items = response
                    .get("result")
                    .and_then(|result| result.get("prompts"))
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for item in items {
                    if let Some(entry) = self.prompt_entry_from_value(server, item, discovered_at) {
                        prompts.insert(entry.public_name.clone(), entry);
                    }
                }
            }
            if self.discovery.aggregate_resources && server.expose_resources {
                let response = self
                    .request_upstream_json(
                        ctx,
                        downstream_session_id,
                        server,
                        "resources/list",
                        json!({}),
                    )
                    .await?;
                let items = response
                    .get("result")
                    .and_then(|result| result.get("resources"))
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for item in items {
                    if let Some(entry) = self.resource_entry_from_value(server, item, discovered_at)
                    {
                        resources.insert(entry.public_uri.clone(), entry);
                    }
                }
            }
        }

        let mut catalog = self.catalog.write().await;
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
        if changed || catalog.version == 0 {
            catalog.version = catalog.version.saturating_add(1);
        }
        catalog.last_refreshed_at = Some(Instant::now());
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
        let new_tool = !old_catalog.tools.contains_key(&public_name);
        let hidden_by_discovery = (new_tool
            && self.discovery.on_new_tool == DiscoveryBehavior::HideUntilConfigured
            && !explicitly_configured)
            || (schema_changed
                && self.discovery.on_schema_change == DiscoveryBehavior::HideUntilConfigured);
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
            return json_rpc_error(
                envelope.id.clone(),
                -32006,
                "MCP catalog unavailable",
                Some(error),
            );
        }
        let catalog = self.catalog.read().await;
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
        let tools: Vec<Value> = catalog
            .tools
            .values()
            .filter(|entry| {
                entry.enabled
                    || !(self.discovery.hide_denied_items || self.policy.hide_denied_tools)
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
            return json_rpc_error(
                envelope.id.clone(),
                -32006,
                "MCP catalog unavailable",
                Some(error),
            );
        }
        let catalog = self.catalog.read().await;
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
            return json_rpc_error(
                envelope.id.clone(),
                -32006,
                "MCP catalog unavailable",
                Some(error),
            );
        }
        let catalog = self.catalog.read().await;
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

    async fn route_tool_call(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
        envelope: &McpEnvelope,
        downstream_session_id: &str,
    ) -> PluginResult {
        if let Err(error) = self.ensure_catalog(ctx, downstream_session_id).await {
            return json_rpc_error(
                envelope.id.clone(),
                -32006,
                "MCP catalog unavailable",
                Some(error),
            );
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
        let catalog = self.catalog.read().await;
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
            let arguments = envelope
                .params
                .as_ref()
                .and_then(|params| params.get("arguments"))
                .unwrap_or(&Value::Null);
            if self.observability.log_argument_hash {
                ctx.metadata
                    .insert("mcp.arguments_hash".to_string(), hash_value(arguments));
            }
            if self.observability.log_raw_arguments {
                ctx.metadata
                    .insert("mcp.arguments".to_string(), arguments.to_string());
            }
            match validate_json_schema(&entry.input_schema, arguments) {
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
        ctx.metadata
            .insert(METADATA_REWRITE_KEY.to_string(), "true".to_string());
        PluginResult::Continue
    }

    async fn route_prompt_get(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
        envelope: &McpEnvelope,
        downstream_session_id: &str,
    ) -> PluginResult {
        if let Err(error) = self.ensure_catalog(ctx, downstream_session_id).await {
            return json_rpc_error(
                envelope.id.clone(),
                -32006,
                "MCP catalog unavailable",
                Some(error),
            );
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
        let catalog = self.catalog.read().await;
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
                .insert("mcp.prompt_name".to_string(), public_name);
            ctx.metadata
                .insert("mcp.server_id".to_string(), entry.server_id.clone());
            ctx.metadata
                .insert("mcp.upstream_prompt_name".to_string(), entry.upstream_name);
        }
        self.set_route_to_server(ctx, headers, server, Some(downstream_session_id));
        ctx.metadata
            .insert(METADATA_REWRITE_KEY.to_string(), "true".to_string());
        PluginResult::Continue
    }

    async fn route_resource_read(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
        envelope: &McpEnvelope,
        downstream_session_id: &str,
    ) -> PluginResult {
        if let Err(error) = self.ensure_catalog(ctx, downstream_session_id).await {
            return json_rpc_error(
                envelope.id.clone(),
                -32006,
                "MCP catalog unavailable",
                Some(error),
            );
        }
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
        let catalog = self.catalog.read().await;
        let Some(entry) = catalog.resources.get(&public_uri).cloned() else {
            return json_rpc_error(envelope.id.clone(), -32007, "Unknown MCP resource", None);
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
                .insert("mcp.resource_uri".to_string(), public_uri);
            ctx.metadata
                .insert("mcp.server_id".to_string(), entry.server_id.clone());
        }
        self.set_route_to_server(ctx, headers, server, Some(downstream_session_id));
        ctx.metadata
            .insert(METADATA_REWRITE_KEY.to_string(), "true".to_string());
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

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
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
                self.session_store.remove(&session_id);
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
            return PluginResult::Continue;
        }
        if !Self::content_type_is_json(headers) {
            return json_rpc_error(None, -32600, "Invalid MCP JSON-RPC request", None);
        }
        let Some(body) = self.request_body(ctx) else {
            return json_rpc_error(None, -32600, "Invalid MCP JSON-RPC request", None);
        };
        let envelope = match parse_mcp_envelope(body) {
            Ok(envelope) => envelope,
            Err(_) => return json_rpc_error(None, -32600, "Invalid MCP JSON-RPC request", None),
        };
        self.emit_envelope_metadata(ctx, &envelope);
        let protocol_version = self.mark_protocol_version(ctx, headers, Some(&envelope));
        if let Some(session_id) = self.downstream_session_id_from_headers(headers) {
            ctx.metadata
                .insert("mcp.session.downstream".to_string(), hash_str(&session_id));
        }

        if self.mode == McpGatewayMode::TransparentProxy {
            return self.handle_transparent_post(ctx, headers, &envelope);
        }

        let method = envelope.method.as_deref().unwrap_or_default();
        match method {
            "initialize" => {
                let version =
                    protocol_version.unwrap_or_else(|| self.supported_protocol_versions[0].clone());
                if !self.supported_protocol_versions.contains(&version) {
                    return json_rpc_error(
                        envelope.id.clone(),
                        -32602,
                        "Unsupported MCP protocol version",
                        None,
                    );
                }
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
                let downstream_session_id = self.create_downstream_session(
                    version.clone(),
                    client_info,
                    client_capabilities,
                );
                ctx.metadata.insert(
                    "mcp.session.downstream".to_string(),
                    hash_str(&downstream_session_id),
                );
                ctx.metadata.insert(
                    "mcp.route_decision".to_string(),
                    "synthetic_response".to_string(),
                );
                self.synthetic_initialize_response(&envelope, &version, &downstream_session_id)
            }
            "notifications/initialized" | "ping" => {
                ctx.metadata.insert(
                    "mcp.route_decision".to_string(),
                    "synthetic_response".to_string(),
                );
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
                let Some(session_id) = self.downstream_session_id_from_headers(headers) else {
                    return json_rpc_error(
                        envelope.id.clone(),
                        -32005,
                        "Upstream MCP session unavailable",
                        None,
                    );
                };
                self.aggregate_tools_list(ctx, &envelope, &session_id).await
            }
            "tools/call" => {
                let Some(session_id) = self.downstream_session_id_from_headers(headers) else {
                    return json_rpc_error(
                        envelope.id.clone(),
                        -32005,
                        "Upstream MCP session unavailable",
                        None,
                    );
                };
                self.route_tool_call(ctx, headers, &envelope, &session_id)
                    .await
            }
            "prompts/list" => {
                let Some(session_id) = self.downstream_session_id_from_headers(headers) else {
                    return json_rpc_error(
                        envelope.id.clone(),
                        -32005,
                        "Upstream MCP session unavailable",
                        None,
                    );
                };
                self.aggregate_prompts_list(ctx, &envelope, &session_id)
                    .await
            }
            "prompts/get" => {
                let Some(session_id) = self.downstream_session_id_from_headers(headers) else {
                    return json_rpc_error(
                        envelope.id.clone(),
                        -32005,
                        "Upstream MCP session unavailable",
                        None,
                    );
                };
                self.route_prompt_get(ctx, headers, &envelope, &session_id)
                    .await
            }
            "resources/list" | "resources/templates/list" => {
                let Some(session_id) = self.downstream_session_id_from_headers(headers) else {
                    return json_rpc_error(
                        envelope.id.clone(),
                        -32005,
                        "Upstream MCP session unavailable",
                        None,
                    );
                };
                self.aggregate_resources_list(ctx, &envelope, &session_id)
                    .await
            }
            "resources/read" => {
                let Some(session_id) = self.downstream_session_id_from_headers(headers) else {
                    return json_rpc_error(
                        envelope.id.clone(),
                        -32005,
                        "Upstream MCP session unavailable",
                        None,
                    );
                };
                self.route_resource_read(ctx, headers, &envelope, &session_id)
                    .await
            }
            _ if self.capabilities.passthrough_unknown_methods => {
                if let Some(server) = self.primary_server() {
                    let session_id = self.downstream_session_id_from_headers(headers);
                    self.set_route_to_server(ctx, headers, server, session_id.as_deref());
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
            _ => json_rpc_error(envelope.id.clone(), -32601, "MCP method not found", None),
        }
    }

    async fn transform_request_body(
        &self,
        body: &[u8],
        _content_type: Option<&str>,
        _request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if !self.enabled || self.mode != McpGatewayMode::AggregateRouter {
            return None;
        }
        let mut value: Value = serde_json::from_slice(body).ok()?;
        let method = value.get("method")?.as_str()?.to_string();
        let params = value.get_mut("params")?.as_object_mut()?;
        match method.as_str() {
            "tools/call" => {
                let public_name = params.get("name")?.as_str()?.to_string();
                let catalog = self.catalog.read().await;
                let entry = catalog.tools.get(&public_name)?;
                params.insert(
                    "name".to_string(),
                    Value::String(entry.upstream_name.clone()),
                );
            }
            "prompts/get" => {
                let public_name = params.get("name")?.as_str()?.to_string();
                let catalog = self.catalog.read().await;
                let entry = catalog.prompts.get(&public_name)?;
                params.insert(
                    "name".to_string(),
                    Value::String(entry.upstream_name.clone()),
                );
            }
            "resources/read" => {
                let public_uri = params.get("uri")?.as_str()?.to_string();
                let catalog = self.catalog.read().await;
                let entry = catalog.resources.get(&public_uri)?;
                params.insert("uri".to_string(), Value::String(entry.upstream_uri.clone()));
            }
            _ => return None,
        }
        serde_json::to_vec(&value).ok()
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.servers
            .values()
            .filter(|server| server.enabled)
            .map(|server| server.target.host.clone())
            .collect()
    }
}

fn parse_mcp_envelope(body: &[u8]) -> Result<McpEnvelope, String> {
    let value: Value = serde_json::from_slice(body).map_err(|error| error.to_string())?;
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

fn validate_json_schema(schema: &Value, instance: &Value) -> Result<(), String> {
    let validator =
        jsonschema::validator_for(schema).map_err(|error| format!("invalid schema: {error}"))?;
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
    if internal_detail.is_some() {
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
    Ok(McpSessionConfig {
        downstream_session_header: optional_string_from_object(
            sessions,
            "downstream_session_header",
        )?
        .unwrap_or_else(|| "mcp-session-id".to_string()),
        upstream_session_header: optional_string_from_object(sessions, "upstream_session_header")?
            .unwrap_or_else(|| "mcp-session-id".to_string()),
        initialize_upstreams,
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
    Ok(McpValidationConfig {
        validate_tool_arguments: optional_bool_from_object(validation, "validate_tool_arguments")?
            .unwrap_or(true),
        validate_tool_results: optional_bool_from_object(validation, "validate_tool_results")?
            .unwrap_or(false),
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
