//! Pre-resolved plugin cache for O(1) per-request plugin lookup.
//!
//! Plugins are created once at config load time — not per-request. This is
//! critical for stateful plugins (e.g., `rate_limiting`) whose internal DashMap
//! counters must persist across requests. Without caching, a fresh rate limiter
//! would be created per request and limits would never be enforced.
//!
//! Each proxy gets a merged plugin list: global plugins + proxy-scoped plugins,
//! sorted by priority. Pre-computed flags (`requires_response_body_buffering`,
//! `requires_request_body_buffering`, `requires_ws_frame_hooks`, and
//! protocol-scoped response-stream hooks) enable O(1)
//! upper-bound decisions on the hot path instead of per-request plugin
//! iteration.
//!
//! Incremental updates via `apply_delta()` preserve unchanged proxy plugin
//! lists (including their stateful instances) and only rebuild affected proxies.

use arc_swap::ArcSwap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use crate::config::types::{GatewayConfig, PluginScope};
use tracing::{error, warn};

use crate::config::types::PluginConfig;
use crate::plugins::utils::jwks_cache::retain_active_requirements;
use crate::plugins::{
    Plugin, PluginFailurePolicy, PluginHttpClient, ProxyProtocol, create_plugin_with_http_client,
};

// ---------------------------------------------------------------------------
// PriorityOverridePlugin — wraps any plugin with a user-specified priority
// ---------------------------------------------------------------------------

use crate::plugins::{
    PluginResult, RequestContext, ResponseStreamInspector, StreamConnectionContext,
    StreamTransactionSummary, TransactionSummary, UdpDatagramContext, UdpDatagramVerdict,
    WebSocketFrameDirection,
};
use async_trait::async_trait;

/// Thin wrapper that overrides a plugin's built-in priority with a
/// user-configured value from `PluginConfig.priority_override`.
struct PriorityOverridePlugin {
    inner: Arc<dyn Plugin>,
    priority: u16,
}

#[async_trait]
impl Plugin for PriorityOverridePlugin {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn priority(&self) -> u16 {
        self.priority
    }
    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        self.inner.on_request_received(ctx).await
    }
    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &crate::consumer_index::ConsumerIndex,
    ) -> PluginResult {
        self.inner.authenticate(ctx, consumer_index).await
    }
    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        self.inner.authorize(ctx).await
    }
    fn is_authorize_plugin(&self) -> bool {
        self.inner.is_authorize_plugin()
    }
    fn modifies_request_headers(&self) -> bool {
        self.inner.modifies_request_headers()
    }
    fn modifies_request_body(&self) -> bool {
        self.inner.modifies_request_body()
    }
    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.inner.requires_request_body_before_before_proxy()
    }
    fn requires_request_body_before_authenticate(&self) -> bool {
        self.inner.requires_request_body_before_authenticate()
    }
    fn requires_request_body_buffering(&self) -> bool {
        self.inner.requires_request_body_buffering()
    }
    fn needs_request_body_bytes(&self) -> bool {
        self.inner.needs_request_body_bytes()
    }
    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut std::collections::HashMap<String, String>,
    ) -> PluginResult {
        self.inner.before_proxy(ctx, headers).await
    }
    fn is_backend_admission_plugin(&self) -> bool {
        self.inner.is_backend_admission_plugin()
    }
    fn try_backend_admission(
        &self,
        ctx: &RequestContext,
        admission: &crate::plugins::BackendAdmissionContext<'_>,
    ) -> crate::plugins::BackendAdmissionDecision {
        self.inner.try_backend_admission(ctx, admission)
    }
    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        self.inner.should_buffer_request_body(ctx)
    }
    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut std::collections::HashMap<String, String>,
    ) -> PluginResult {
        self.inner
            .after_proxy(ctx, response_status, response_headers)
            .await
    }
    fn may_modify_response_content_type(
        &self,
        ctx: &RequestContext,
        response_content_type: Option<&str>,
    ) -> bool {
        self.inner
            .may_modify_response_content_type(ctx, response_content_type)
    }
    fn may_add_response_cache_control_no_transform(
        &self,
        ctx: &RequestContext,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        self.inner
            .may_add_response_cache_control_no_transform(ctx, response_headers)
    }
    fn may_add_response_strong_etag(
        &self,
        ctx: &RequestContext,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        self.inner
            .may_add_response_strong_etag(ctx, response_headers)
    }
    fn simulate_after_proxy_response_headers(
        &self,
        ctx: &mut RequestContext,
        response_headers: &mut std::collections::HashMap<String, String>,
    ) {
        self.inner
            .simulate_after_proxy_response_headers(ctx, response_headers);
    }
    fn needs_later_response_cache_control_no_transform(&self) -> bool {
        self.inner.needs_later_response_cache_control_no_transform()
    }
    fn needs_later_response_strong_etag(&self) -> bool {
        self.inner.needs_later_response_strong_etag()
    }
    fn applies_after_proxy_on_reject(&self) -> bool {
        self.inner.applies_after_proxy_on_reject()
    }
    fn requires_response_body_buffering(&self) -> bool {
        self.inner.requires_response_body_buffering()
    }
    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        self.inner.should_buffer_response_body(ctx)
    }
    fn may_release_response_body_under_retries(&self, ctx: &RequestContext) -> bool {
        self.inner.may_release_response_body_under_retries(ctx)
    }
    fn should_release_response_body_under_retries(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        self.inner.should_release_response_body_under_retries(
            ctx,
            response_status,
            response_headers,
        )
    }
    fn should_release_response_body_before_content_type_rewrite(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        self.inner
            .should_release_response_body_before_content_type_rewrite(
                ctx,
                response_status,
                response_headers,
            )
    }
    fn should_release_response_body_for_later_no_transform(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        self.inner
            .should_release_response_body_for_later_no_transform(
                ctx,
                response_status,
                response_headers,
            )
    }
    fn should_release_response_body_for_later_strong_etag(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        self.inner
            .should_release_response_body_for_later_strong_etag(
                ctx,
                response_status,
                response_headers,
            )
    }
    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        response_status: u16,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        // Must forward, not fall back to the trait default (which ignores
        // content-type): a priority-overridden inspect-mode policy needs the
        // buffer->stream downgrade for SSE, else it buffers an unbounded stream.
        self.inner.should_buffer_response_body_for_content_type(
            ctx,
            content_type,
            response_status,
            response_headers,
        )
    }
    async fn on_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &std::collections::HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        self.inner
            .on_response_body(ctx, response_status, response_headers, body)
            .await
    }
    async fn normalize_response_body_with_context(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        body: &[u8],
        content_type: Option<&str>,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        self.inner
            .normalize_response_body_with_context(
                ctx,
                response_status,
                body,
                content_type,
                response_headers,
            )
            .await
    }
    async fn transform_request_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        request_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        self.inner
            .transform_request_body(body, content_type, request_headers)
            .await
    }
    async fn transform_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        request_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        self.inner
            .transform_request_body_with_context(ctx, body, content_type, request_headers)
            .await
    }
    async fn on_final_request_body(
        &self,
        headers: &std::collections::HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        self.inner.on_final_request_body(headers, body).await
    }
    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &std::collections::HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        self.inner
            .on_final_request_body_with_context(ctx, headers, body)
            .await
    }
    fn needs_final_request_body_context(&self) -> bool {
        self.inner.needs_final_request_body_context()
    }
    async fn transform_response_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        self.inner
            .transform_response_body(body, content_type, response_headers)
            .await
    }
    async fn transform_response_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        self.inner
            .transform_response_body_with_context(ctx, body, content_type, response_headers)
            .await
    }
    fn on_response_body_transformed(
        &self,
        ctx: &mut RequestContext,
        response_headers: &mut std::collections::HashMap<String, String>,
    ) {
        self.inner
            .on_response_body_transformed(ctx, response_headers);
    }
    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &std::collections::HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        self.inner
            .on_final_response_body(ctx, response_status, response_headers, body)
            .await
    }
    fn requires_response_committed_hook(&self) -> bool {
        self.inner.requires_response_committed_hook()
    }
    async fn on_response_committed(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &std::collections::HashMap<String, String>,
        body: &[u8],
    ) {
        self.inner
            .on_response_committed(ctx, response_status, response_headers, body)
            .await;
    }
    async fn on_response_stream_terminated(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        outcome: &crate::proxy::deferred_log::BodyOutcome,
    ) {
        self.inner
            .on_response_stream_terminated(ctx, response_status, outcome)
            .await;
    }
    async fn log(&self, summary: &TransactionSummary) {
        self.inner.log(summary).await;
    }
    fn is_auth_plugin(&self) -> bool {
        self.inner.is_auth_plugin()
    }
    fn authentication_challenge(&self) -> Option<&'static str> {
        self.inner.authentication_challenge()
    }
    fn start_background_tasks(&self) -> Result<(), String> {
        self.inner.start_background_tasks()
    }
    fn warmup_hostnames(&self) -> Vec<String> {
        self.inner.warmup_hostnames()
    }
    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        self.inner.supported_protocols()
    }
    fn tracked_keys_count(&self) -> Option<usize> {
        self.inner.tracked_keys_count()
    }
    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        self.inner.on_stream_connect(ctx).await
    }
    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.inner.on_stream_disconnect(summary).await;
    }
    fn requires_ws_frame_hooks(&self) -> bool {
        self.inner.requires_ws_frame_hooks()
    }
    async fn on_ws_frame(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        message: &tokio_tungstenite::tungstenite::Message,
    ) -> Option<tokio_tungstenite::tungstenite::Message> {
        self.inner
            .on_ws_frame(proxy_id, connection_id, direction, message)
            .await
    }
    fn requires_response_stream_hooks(&self) -> bool {
        self.inner.requires_response_stream_hooks()
    }
    fn on_response_stream_selected(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        content_type: Option<&str>,
    ) {
        self.inner
            .on_response_stream_selected(ctx, response_status, content_type);
    }
    fn forces_reqwest_dispatch(&self, ctx: &RequestContext) -> bool {
        self.inner.forces_reqwest_dispatch(ctx)
    }
    fn response_stream_inspector(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        content_type: Option<&str>,
    ) -> Option<Box<dyn ResponseStreamInspector>> {
        self.inner
            .response_stream_inspector(ctx, response_status, content_type)
    }
    fn requires_udp_datagram_hooks(&self) -> bool {
        self.inner.requires_udp_datagram_hooks()
    }
    fn requires_stream_first_bytes(&self) -> bool {
        self.inner.requires_stream_first_bytes()
    }
    fn requires_stream_first_bytes_decrypted(&self) -> bool {
        self.inner.requires_stream_first_bytes_decrypted()
    }
    fn stream_first_bytes_min_len(&self) -> usize {
        self.inner.stream_first_bytes_min_len()
    }
    async fn on_udp_datagram(&self, ctx: &UdpDatagramContext<'_>) -> UdpDatagramVerdict {
        self.inner.on_udp_datagram(ctx).await
    }
    fn requires_ws_disconnect_hooks(&self) -> bool {
        self.inner.requires_ws_disconnect_hooks()
    }
    async fn on_ws_disconnect(&self, ctx: &crate::plugins::WsDisconnectContext) {
        self.inner.on_ws_disconnect(ctx).await;
    }
    fn requires_decoded_query_params(&self) -> bool {
        self.inner.requires_decoded_query_params()
    }
    fn active_jwks_uris(&self) -> Vec<String> {
        self.inner.active_jwks_uris()
    }
    fn active_jwks_refresh_requirements(&self) -> Vec<(String, Duration)> {
        self.inner.active_jwks_refresh_requirements()
    }
}

/// Try to create a plugin and apply `priority_override` from the plugin config.
///
/// Enabled plugin configs are load-bearing configuration: unknown plugin names
/// and required-plugin validation failures reject the whole cache generation.
/// Optional plugins may be omitted only when their registration metadata allows
/// fail-open behavior.
fn try_create_plugin(
    pc: &PluginConfig,
    http_client: &PluginHttpClient,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    match create_plugin_with_http_client(&pc.plugin_name, &pc.config, http_client.clone()) {
        Ok(Some(plugin)) => {
            let plugin: Arc<dyn Plugin> = if let Some(priority) = pc.priority_override {
                Arc::new(PriorityOverridePlugin {
                    inner: plugin,
                    priority,
                })
            } else {
                plugin
            };
            Ok(Some(plugin))
        }
        Ok(None) => {
            if crate::plugins::removed_plugin_registration(&pc.plugin_name).is_some() {
                let msg = format!(
                    "Removed security plugin '{}' (plugin_config_id={}) is not supported; migrate to a supported auth plugin before startup/reload",
                    pc.plugin_name, pc.id
                );
                error!("FATAL: {}", msg);
                Err(msg)
            } else {
                let msg = format!(
                    "Unknown enabled plugin '{}' (plugin_config_id={}, scope={:?}, proxy_id={})",
                    pc.plugin_name,
                    pc.id,
                    pc.scope,
                    pc.proxy_id.as_deref().unwrap_or("<none>")
                );
                error!("Config rejected: {}", msg);
                Err(msg)
            }
        }
        Err(e) => {
            let failure_policy = crate::plugins::plugin_failure_policy(&pc.plugin_name)
                .unwrap_or(PluginFailurePolicy::FailClosed);
            let msg = format!(
                "Plugin '{}' (plugin_config_id={}, scope={:?}, proxy_id={}) config validation failed: {}",
                pc.plugin_name,
                pc.id,
                pc.scope,
                pc.proxy_id.as_deref().unwrap_or("<none>"),
                e
            );
            if failure_policy == PluginFailurePolicy::OptionalFailOpen {
                warn!("Optional plugin omitted after validation failure: {}", msg);
                Ok(None)
            } else {
                error!("Config rejected: {}", msg);
                Err(msg)
            }
        }
    }
}

/// A list of plugins shared across requests via Arc.
type PluginList = Arc<Vec<Arc<dyn Plugin>>>;
/// Map from proxy_id to its pre-resolved plugin list.
type ProxyPluginMap = HashMap<String, PluginList>;
/// Map from proxy_id to whether any plugin requires response body buffering.
type BufferingMap = HashMap<String, bool>;
/// Map from proxy_id to whether any plugin may require request body buffering
/// for at least some requests.
type RequestBufferingMap = HashMap<String, bool>;
/// Map from proxy_id to whether any plugin requires per-frame WebSocket hooks.
type WsFrameMap = HashMap<String, bool>;
/// Map from proxy_group plugin_config_id to its shared plugin instance.
type ProxyGroupInstanceMap = HashMap<String, ProxyGroupPluginInstance>;

#[derive(Clone)]
struct ProxyGroupPluginInstance {
    plugin: Arc<dyn Plugin>,
    config: PluginConfig,
}

fn remove_shadowed_global_plugin(
    plugins: &mut Vec<Arc<dyn Plugin>>,
    global_ptrs: &HashSet<usize>,
    plugin_name: &str,
) {
    plugins.retain(|plugin| {
        plugin.name() != plugin_name
            || !global_ptrs.contains(&(Arc::as_ptr(plugin) as *const () as usize))
    });
}

fn same_proxy_group_plugin_config(left: &PluginConfig, right: &PluginConfig) -> bool {
    left.id == right.id
        && left.namespace == right.namespace
        && left.plugin_name == right.plugin_name
        && left.config == right.config
        && left.scope == right.scope
        && left.proxy_id == right.proxy_id
        && left.enabled == right.enabled
        && left.priority_override == right.priority_override
}

// ---------------------------------------------------------------------------
// Per-protocol phase data — precomputed at config reload time
// ---------------------------------------------------------------------------

/// Bitflags for per-protocol plugin capability checks. Avoids per-request
/// `plugins.iter().any(|p| p.some_flag())` scans on the hot path.
#[derive(Clone, Copy, Default)]
pub struct PluginCapabilities(u16);

impl PluginCapabilities {
    pub const HAS_AUTH_PLUGINS: u16 = 1 << 0;
    pub const MODIFIES_REQUEST_HEADERS: u16 = 1 << 1;
    pub const MODIFIES_REQUEST_BODY: u16 = 1 << 2;
    pub const HAS_BODY_BEFORE_BEFORE_PROXY: u16 = 1 << 3;
    pub const NEEDS_REQUEST_BODY_BYTES: u16 = 1 << 4;
    pub const HAS_BODY_BEFORE_AUTHENTICATE: u16 = 1 << 5;
    pub const NEEDS_DECODED_QUERY_PARAMS: u16 = 1 << 6;
    pub const NEEDS_FINAL_REQUEST_BODY_CONTEXT: u16 = 1 << 7;
    pub const HAS_RESPONSE_COMMITTED_HOOK: u16 = 1 << 8;
    pub const HAS_RESPONSE_STREAM_HOOKS: u16 = 1 << 9;

    #[inline(always)]
    pub fn has(self, flag: u16) -> bool {
        self.0 & flag != 0
    }
}

/// Pre-computed per-protocol plugin phase data for a single proxy.
/// Built at config reload time so the hot path does zero filtering or allocation.
#[derive(Clone)]
pub struct PluginPhaseData {
    /// Auth plugins only (pre-filtered from the protocol plugin list).
    pub auth_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    /// Authorization plugins only (pre-filtered from the protocol plugin list).
    pub authorize_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    /// Backend-admission plugins only (pre-filtered from the protocol plugin list).
    pub backend_admission_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    /// Capability bitset for fast boolean checks.
    pub capabilities: PluginCapabilities,
}

/// Build `PluginPhaseData` from a protocol-filtered plugin list.
fn build_phase_data(plugins: &[Arc<dyn Plugin>]) -> PluginPhaseData {
    let mut caps = 0u16;
    let mut auth = Vec::new();
    let mut authorize = Vec::new();
    let mut backend_admission = Vec::new();
    for p in plugins {
        if p.is_auth_plugin() {
            caps |= PluginCapabilities::HAS_AUTH_PLUGINS;
            auth.push(Arc::clone(p));
        }
        if p.is_authorize_plugin() {
            authorize.push(Arc::clone(p));
        }
        if p.is_backend_admission_plugin() {
            backend_admission.push(Arc::clone(p));
        }
        if p.modifies_request_headers() {
            caps |= PluginCapabilities::MODIFIES_REQUEST_HEADERS;
        }
        if p.modifies_request_body() {
            caps |= PluginCapabilities::MODIFIES_REQUEST_BODY;
        }
        if p.requires_request_body_before_before_proxy() {
            caps |= PluginCapabilities::HAS_BODY_BEFORE_BEFORE_PROXY;
        }
        if p.requires_request_body_before_authenticate() {
            caps |= PluginCapabilities::HAS_BODY_BEFORE_AUTHENTICATE;
        }
        if p.needs_request_body_bytes() {
            caps |= PluginCapabilities::NEEDS_REQUEST_BODY_BYTES;
        }
        if p.requires_decoded_query_params() {
            caps |= PluginCapabilities::NEEDS_DECODED_QUERY_PARAMS;
        }
        if p.needs_final_request_body_context() {
            caps |= PluginCapabilities::NEEDS_FINAL_REQUEST_BODY_CONTEXT;
        }
        if p.requires_response_committed_hook() {
            caps |= PluginCapabilities::HAS_RESPONSE_COMMITTED_HOOK;
        }
        if p.requires_response_stream_hooks() {
            caps |= PluginCapabilities::HAS_RESPONSE_STREAM_HOOKS;
        }
    }
    PluginPhaseData {
        auth_plugins: Arc::new(auth),
        authorize_plugins: Arc::new(authorize),
        backend_admission_plugins: Arc::new(backend_admission),
        capabilities: PluginCapabilities(caps),
    }
}

/// Filter a plugin list to only those supporting a given protocol.
fn filter_for_protocol(
    plugins: &[Arc<dyn Plugin>],
    protocol: ProxyProtocol,
) -> Arc<Vec<Arc<dyn Plugin>>> {
    Arc::new(
        plugins
            .iter()
            .filter(|p| p.supported_protocols().contains(&protocol))
            .cloned()
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// ProtocolSnapshot — bundles protocol-filtered plugins + phase data for
// atomic swap via a single ArcSwap. Ensures a request always reads a
// consistent pair of (plugin list, phase data) for the same config generation.
// ---------------------------------------------------------------------------

/// Per-proxy, per-protocol entry: the filtered plugin list and its derived phase data.
#[derive(Clone)]
struct ProtocolEntry {
    plugins: PluginList,
    phase: PluginPhaseData,
}

/// All per-proxy protocol data, swapped atomically as one unit.
struct ProtocolSnapshot {
    /// proxy_id → (protocol → ProtocolEntry)
    proxy: HashMap<String, HashMap<ProxyProtocol, ProtocolEntry>>,
    /// Global fallback: protocol → ProtocolEntry
    global: HashMap<ProxyProtocol, ProtocolEntry>,
}

const ALL_PROXY_PROTOCOLS: [ProxyProtocol; 5] = [
    ProxyProtocol::Http,
    ProxyProtocol::Grpc,
    ProxyProtocol::WebSocket,
    ProxyProtocol::Tcp,
    ProxyProtocol::Udp,
];

fn build_protocol_entry(plugins: &[Arc<dyn Plugin>], proto: ProxyProtocol) -> ProtocolEntry {
    let filtered = filter_for_protocol(plugins, proto);
    let phase = build_phase_data(&filtered);
    ProtocolEntry {
        plugins: filtered,
        phase,
    }
}

/// Build the full protocol snapshot from the plugin map + global fallback.
fn build_protocol_snapshot(
    proxy_map: &ProxyPluginMap,
    globals: &[Arc<dyn Plugin>],
) -> ProtocolSnapshot {
    let mut proxy = HashMap::with_capacity(proxy_map.len());
    for (proxy_id, plugins) in proxy_map {
        let mut inner = HashMap::with_capacity(ALL_PROXY_PROTOCOLS.len());
        for &proto in &ALL_PROXY_PROTOCOLS {
            inner.insert(proto, build_protocol_entry(plugins, proto));
        }
        proxy.insert(proxy_id.clone(), inner);
    }

    let mut global = HashMap::with_capacity(ALL_PROXY_PROTOCOLS.len());
    for &proto in &ALL_PROXY_PROTOCOLS {
        global.insert(proto, build_protocol_entry(globals, proto));
    }

    ProtocolSnapshot { proxy, global }
}

/// Collect all JWKS URIs actively referenced by `jwks_auth` plugin instances
/// across all proxies and global plugins. Used to clean up stale JWKS cache
/// entries (and abort their background refresh tasks) on config reload.
fn collect_active_jwks_requirements(
    proxy_map: &ProxyPluginMap,
    globals: &[Arc<dyn Plugin>],
) -> HashMap<String, Duration> {
    let mut requirements = HashMap::new();
    for plugins in proxy_map.values() {
        for plugin in plugins.iter() {
            for (uri, interval) in plugin.active_jwks_refresh_requirements() {
                requirements
                    .entry(uri)
                    .and_modify(|current: &mut Duration| *current = (*current).min(interval))
                    .or_insert(interval);
            }
        }
    }
    for plugin in globals {
        for (uri, interval) in plugin.active_jwks_refresh_requirements() {
            requirements
                .entry(uri)
                .and_modify(|current: &mut Duration| *current = (*current).min(interval))
                .or_insert(interval);
        }
    }
    requirements
}

fn start_background_tasks(
    proxy_map: &ProxyPluginMap,
    globals: &[Arc<dyn Plugin>],
) -> Result<(), String> {
    let mut started = HashSet::new();
    for plugin in globals
        .iter()
        .chain(proxy_map.values().flat_map(|plugins| plugins.iter()))
    {
        let pointer = Arc::as_ptr(plugin) as *const () as usize;
        if started.insert(pointer) {
            plugin.start_background_tasks().map_err(|error| {
                format!(
                    "plugin '{}' background startup failed: {error}",
                    plugin.name()
                )
            })?;
        }
    }
    Ok(())
}

/// All plugin-cache state swapped as a single unit so a single load observes
/// either the old generation or the new generation, never a partial rebuild.
pub(crate) struct PluginCacheInner {
    /// proxy_id -> pre-resolved plugin list (global + proxy-scoped, merged).
    proxy_plugins: ProxyPluginMap,
    /// Fallback: global plugins only (for proxies with no scoped overrides).
    global_plugins: PluginList,
    /// Pre-computed: does any plugin for this proxy require response body buffering?
    requires_buffering: BufferingMap,
    /// Whether global-only plugins require response body buffering (fallback).
    global_requires_buffering: bool,
    /// Pre-computed: does any plugin for this proxy ever require request body
    /// buffering?
    requires_request_buffering: RequestBufferingMap,
    /// Whether global-only plugins require request body buffering (fallback).
    global_requires_request_buffering: bool,
    /// Pre-computed per-protocol plugin lists + phase data (auth plugin lists,
    /// capability bitsets).
    protocol_snapshot: ProtocolSnapshot,
    /// Pre-computed: does any plugin for this proxy require per-frame WebSocket hooks?
    requires_ws_frame: WsFrameMap,
    /// Whether global-only plugins require per-frame WebSocket hooks (fallback).
    global_requires_ws_frame: bool,
    /// Shared proxy-group plugin instances, keyed by plugin_config_id. Kept
    /// across incremental updates so rebuilt proxies can keep sharing state
    /// with unchanged proxies when the proxy-group config itself did not change.
    proxy_group_plugins: ProxyGroupInstanceMap,
}

impl PluginCacheInner {
    #[allow(clippy::too_many_arguments)]
    fn new(
        proxy_plugins: ProxyPluginMap,
        global_plugins: PluginList,
        requires_buffering: BufferingMap,
        global_requires_buffering: bool,
        requires_request_buffering: RequestBufferingMap,
        global_requires_request_buffering: bool,
        protocol_snapshot: ProtocolSnapshot,
        requires_ws_frame: WsFrameMap,
        global_requires_ws_frame: bool,
        proxy_group_plugins: ProxyGroupInstanceMap,
    ) -> Self {
        Self {
            proxy_plugins,
            global_plugins,
            requires_buffering,
            global_requires_buffering,
            requires_request_buffering,
            global_requires_request_buffering,
            protocol_snapshot,
            requires_ws_frame,
            global_requires_ws_frame,
            proxy_group_plugins,
        }
    }

    pub(crate) fn get_plugins(&self, proxy_id: &str) -> Arc<Vec<Arc<dyn Plugin>>> {
        if let Some(plugins) = self.proxy_plugins.get(proxy_id) {
            Arc::clone(plugins)
        } else {
            Arc::clone(&self.global_plugins)
        }
    }

    fn protocol_entry(&self, proxy_id: &str, protocol: ProxyProtocol) -> Option<&ProtocolEntry> {
        self.protocol_snapshot
            .proxy
            .get(proxy_id)
            .and_then(|m| m.get(&protocol))
            .or_else(|| self.protocol_snapshot.global.get(&protocol))
    }

    pub(crate) fn get_plugins_for_protocol(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> Arc<Vec<Arc<dyn Plugin>>> {
        self.protocol_entry(proxy_id, protocol)
            .map(|entry| Arc::clone(&entry.plugins))
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    pub(crate) fn get_auth_plugins(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> Arc<Vec<Arc<dyn Plugin>>> {
        self.protocol_entry(proxy_id, protocol)
            .map(|entry| Arc::clone(&entry.phase.auth_plugins))
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    pub(crate) fn get_authorize_plugins(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> Arc<Vec<Arc<dyn Plugin>>> {
        self.protocol_entry(proxy_id, protocol)
            .map(|entry| Arc::clone(&entry.phase.authorize_plugins))
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    pub(crate) fn get_backend_admission_plugins(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> Arc<Vec<Arc<dyn Plugin>>> {
        self.protocol_entry(proxy_id, protocol)
            .map(|entry| Arc::clone(&entry.phase.backend_admission_plugins))
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    pub(crate) fn get_capabilities(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> PluginCapabilities {
        self.protocol_entry(proxy_id, protocol)
            .map(|entry| entry.phase.capabilities)
            .unwrap_or_default()
    }

    pub(crate) fn requires_response_body_buffering(&self, proxy_id: &str) -> bool {
        self.requires_buffering
            .get(proxy_id)
            .copied()
            .unwrap_or(self.global_requires_buffering)
    }

    pub(crate) fn requires_request_body_buffering(&self, proxy_id: &str) -> bool {
        self.requires_request_buffering
            .get(proxy_id)
            .copied()
            .unwrap_or(self.global_requires_request_buffering)
    }

    pub(crate) fn requires_ws_frame_hooks(&self, proxy_id: &str) -> bool {
        self.requires_ws_frame
            .get(proxy_id)
            .copied()
            .unwrap_or(self.global_requires_ws_frame)
    }

    pub(crate) fn request_view(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> PluginCacheRequestView {
        PluginCacheRequestView {
            plugins: self.get_plugins_for_protocol(proxy_id, protocol),
            auth_plugins: self.get_auth_plugins(proxy_id, protocol),
            authorize_plugins: self.get_authorize_plugins(proxy_id, protocol),
            backend_admission_plugins: self.get_backend_admission_plugins(proxy_id, protocol),
            capabilities: self.get_capabilities(proxy_id, protocol),
            requires_response_body_buffering: self.requires_response_body_buffering(proxy_id),
            requires_request_body_buffering: self.requires_request_body_buffering(proxy_id),
            requires_ws_frame_hooks: self.requires_ws_frame_hooks(proxy_id),
        }
    }
}

/// Request-scoped plugin cache values for one proxy/protocol pair.
///
/// Built from one cache generation near the start of request handling. It
/// stores only the values that request paths need, so the full plugin-cache
/// snapshot does not stay pinned across plugin/backend awaits.
#[derive(Clone)]
pub struct PluginCacheRequestView {
    plugins: Arc<Vec<Arc<dyn Plugin>>>,
    auth_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    authorize_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    backend_admission_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    capabilities: PluginCapabilities,
    requires_response_body_buffering: bool,
    requires_request_body_buffering: bool,
    requires_ws_frame_hooks: bool,
}

impl PluginCacheRequestView {
    /// Get pre-resolved protocol-filtered plugins from this request view.
    pub fn plugins(&self) -> Arc<Vec<Arc<dyn Plugin>>> {
        Arc::clone(&self.plugins)
    }

    /// Get pre-computed auth plugins from this request view.
    pub fn auth_plugins(&self) -> Arc<Vec<Arc<dyn Plugin>>> {
        Arc::clone(&self.auth_plugins)
    }

    /// Get pre-computed authorization plugins from this request view.
    pub fn authorize_plugins(&self) -> Arc<Vec<Arc<dyn Plugin>>> {
        Arc::clone(&self.authorize_plugins)
    }

    /// Get pre-computed backend admission plugins from this request view.
    pub fn backend_admission_plugins(&self) -> Arc<Vec<Arc<dyn Plugin>>> {
        Arc::clone(&self.backend_admission_plugins)
    }

    /// Get pre-computed capability bitset from this request view.
    pub fn capabilities(&self) -> PluginCapabilities {
        self.capabilities
    }

    /// Check response-body buffering requirement from this request view.
    pub fn requires_response_body_buffering(&self) -> bool {
        self.requires_response_body_buffering
    }

    /// Check request-body buffering requirement from this request view.
    pub fn requires_request_body_buffering(&self) -> bool {
        self.requires_request_body_buffering
    }

    /// Check WebSocket frame-hook requirement from this request view.
    pub fn requires_ws_frame_hooks(&self) -> bool {
        self.requires_ws_frame_hooks
    }

    /// Check whether any protocol-compatible plugin opted into response-stream
    /// inspection or terminal hooks. Precomputed at cache-build time so the
    /// common response path does not scan plugins per request.
    pub fn requires_response_stream_hooks(&self) -> bool {
        self.capabilities
            .has(PluginCapabilities::HAS_RESPONSE_STREAM_HOOKS)
    }
}

/// Pre-resolved plugin cache that avoids per-request plugin creation.
///
/// Plugins are created once at config load time and cached per proxy_id.
/// This is critical for stateful plugins like `rate_limiting` whose internal
/// DashMap state must persist across requests. Without caching, a new
/// rate limiter is created per request and limits are never enforced.
///
/// All mutable state is bundled inside a single `ArcSwap<PluginCacheInner>`
/// so every config reload swaps all fields atomically — readers see either
/// the old generation or the new generation, never a mix.
pub struct PluginCache {
    inner: ArcSwap<PluginCacheInner>,
    /// Shared HTTP client for plugins that make outbound network calls.
    http_client: PluginHttpClient,
}

impl PluginCache {
    /// Build a new plugin cache from the given config with a default HTTP client.
    #[allow(dead_code)]
    pub fn new(config: &GatewayConfig) -> Result<Self, String> {
        let http_client = PluginHttpClient::default();
        Self::with_http_client(config, http_client)
    }

    /// Build a new plugin cache with a shared HTTP client configured from
    /// the gateway's pool settings. All plugins that make outbound HTTP calls
    /// (http_logging, future OTel exporters, etc.) share this client for
    /// connection reuse and keepalive.
    pub fn with_http_client(
        config: &GatewayConfig,
        http_client: PluginHttpClient,
    ) -> Result<Self, String> {
        let inner = Self::build_inner(config, &http_client)?;
        Ok(Self {
            inner: ArcSwap::new(inner),
            http_client,
        })
    }

    /// Borrow the shared HTTP client configured at construction. Used by
    /// out-of-band runtime tasks (mesh federation poller, etc.) that need
    /// the same DNS cache, pool settings, and TLS configuration as plugins.
    pub fn http_client(&self) -> &PluginHttpClient {
        &self.http_client
    }

    pub(crate) fn build_inner(
        config: &GatewayConfig,
        http_client: &PluginHttpClient,
    ) -> Result<Arc<PluginCacheInner>, String> {
        let (
            proxy_map,
            globals,
            buffering_map,
            global_needs_buffering,
            req_buffering_map,
            global_needs_req_buffering,
            ws_frame_map,
            global_needs_ws_frame,
            proxy_group_plugins,
        ) = Self::build_cache(config, http_client)?;
        let snapshot = build_protocol_snapshot(&proxy_map, &globals);

        Ok(Arc::new(PluginCacheInner::new(
            proxy_map,
            globals,
            buffering_map,
            global_needs_buffering,
            req_buffering_map,
            global_needs_req_buffering,
            snapshot,
            ws_frame_map,
            global_needs_ws_frame,
            proxy_group_plugins,
        )))
    }

    pub(crate) fn build_inner_with_existing_client(
        &self,
        config: &GatewayConfig,
    ) -> Result<Arc<PluginCacheInner>, String> {
        Self::build_inner(config, &self.http_client)
    }

    pub(crate) fn store_inner(&self, inner: Arc<PluginCacheInner>) {
        self.inner.store(inner);
    }

    pub(crate) fn load_inner(&self) -> Arc<PluginCacheInner> {
        self.inner.load_full()
    }

    pub(crate) fn retain_active_uris_for_inner(inner: &PluginCacheInner) {
        let requirements =
            collect_active_jwks_requirements(&inner.proxy_plugins, &inner.global_plugins);
        retain_active_requirements(&requirements);
    }

    /// Build a request-scoped view of plugin-cache values for one proxy/protocol.
    ///
    /// Use this when a request needs more than one plugin-cache-derived value.
    /// The cache is loaded once, all returned values come from that generation,
    /// and the full cache snapshot is released before request processing awaits.
    pub fn request_view(&self, proxy_id: &str, protocol: ProxyProtocol) -> PluginCacheRequestView {
        let inner = self.inner.load();
        inner.request_view(proxy_id, protocol)
    }

    /// Atomically rebuild the cache when config changes.
    /// Old plugin instances (including rate limiter state) are dropped
    /// only after all in-flight requests using them complete.
    ///
    /// Returns `Err` if any enabled plugin config cannot be resolved or fails validation.
    pub fn rebuild(&self, config: &GatewayConfig) -> Result<(), String> {
        let inner = self.build_inner_with_existing_client(config)?;

        // Single atomic swap — readers see either the old or new generation.
        self.store_inner(Arc::clone(&inner));

        // Clean up JWKS cache entries (and their background refresh tasks)
        // after commit so a staged rebuild that fails validation cannot prune
        // the still-live cache.
        Self::retain_active_uris_for_inner(&inner);
        Ok(())
    }

    /// Incrementally update the plugin cache, only rebuilding plugins for
    /// proxies identified in `proxy_ids_to_rebuild`. All other proxy plugin
    /// lists — including their stateful plugin instances (rate limiters, etc.)
    /// — are preserved unchanged.
    ///
    /// Also rebuilds global plugins if `rebuild_globals` is true (i.e., a
    /// global-scoped plugin config was added/modified/removed).
    /// Returns `Err` if any enabled plugin config cannot be resolved or fails
    /// validation during incremental update, matching the behavior of `rebuild()`.
    pub(crate) fn build_delta_inner(
        &self,
        current: &PluginCacheInner,
        config: &GatewayConfig,
        proxy_ids_to_rebuild: &HashSet<String>,
        removed_proxy_ids: &[String],
        rebuild_globals: bool,
    ) -> Result<Arc<PluginCacheInner>, String> {
        let mut plugin_errors: Vec<String> = Vec::new();

        // Rebuild globals if any global plugin config changed
        let new_globals = if rebuild_globals {
            let mut global_plugins: Vec<Arc<dyn Plugin>> = Vec::new();

            // Stage the named-schema registry first so subsequent global /
            // proxy plugins can resolve `schema_ref` against the new state
            // via the reload thread's staging-visibility. The bracket is
            // left OPEN here — commit/abort runs once the rest of the
            // delta build has succeeded or failed (see plugin_errors
            // handling below), so the registry stays atomically tied to
            // the PluginCache that gets swapped in.
            //
            // This runs for every global-plugin rebuild, not just when
            // `transaction_log_schema` itself changed — the bracket is
            // cheap (one Mutex acquire + empty HashMap) and guarantees
            // the registry stays in sync even if a sibling global plugin
            // was the trigger for the rebuild.
            crate::plugins::utils::log_schema::registry::begin_reload();
            for pc in &config.plugin_configs {
                if !pc.enabled || pc.scope != PluginScope::Global {
                    continue;
                }
                if pc.plugin_name != "transaction_log_schema" {
                    continue;
                }
                match try_create_plugin(pc, &self.http_client) {
                    Ok(Some(plugin)) => global_plugins.push(plugin),
                    Ok(None) => {}
                    Err(e) => {
                        error!("Config reload: {}", e);
                        plugin_errors.push(e);
                    }
                }
            }

            for pc in &config.plugin_configs {
                if !pc.enabled {
                    continue;
                }
                if pc.plugin_name == "transaction_log_schema" {
                    continue; // already constructed
                }
                if pc.scope == PluginScope::Global {
                    match try_create_plugin(pc, &self.http_client) {
                        Ok(Some(plugin)) => global_plugins.push(plugin),
                        Ok(None) => {}
                        Err(e) => {
                            error!("Config reload: {}", e);
                            plugin_errors.push(e);
                        }
                    }
                }
            }
            global_plugins.sort_by_key(|p| p.priority());
            Arc::new(global_plugins)
        } else {
            Arc::clone(&current.global_plugins)
        };

        // Build index of proxy-scoped plugin configs for efficient lookup
        let mut proxy_scoped_configs: HashMap<&str, Vec<&crate::config::types::PluginConfig>> =
            HashMap::new();
        let mut proxy_group_configs: HashMap<&str, &crate::config::types::PluginConfig> =
            HashMap::new();
        for pc in &config.plugin_configs {
            if !pc.enabled {
                continue;
            }
            if pc.scope == PluginScope::Proxy
                && let Some(ref proxy_id) = pc.proxy_id
            {
                proxy_scoped_configs
                    .entry(proxy_id.as_str())
                    .or_default()
                    .push(pc);
            } else if pc.scope == PluginScope::ProxyGroup {
                proxy_group_configs.insert(pc.id.as_str(), pc);
            }
        }

        let active_proxy_group_ids: HashSet<&str> = config
            .proxies
            .iter()
            .flat_map(|proxy| proxy.plugins.iter())
            .map(|assoc| assoc.plugin_config_id.as_str())
            .filter(|id| proxy_group_configs.contains_key(*id))
            .collect();

        // Shared ProxyGroup plugin instances. Start with unchanged current
        // instances that are still referenced in the post-delta config. This
        // keeps state shared with unchanged proxies but drops cascade-deleted
        // group state once the last proxy association is removed.
        let mut group_plugin_instances: ProxyGroupInstanceMap = current
            .proxy_group_plugins
            .iter()
            .filter_map(|(id, existing)| {
                if !active_proxy_group_ids.contains(id.as_str()) {
                    return None;
                }
                let pc = proxy_group_configs.get(id.as_str())?;
                if same_proxy_group_plugin_config(&existing.config, pc) {
                    Some((id.clone(), existing.clone()))
                } else {
                    None
                }
            })
            .collect();

        // Clone the current map and patch it
        let mut new_map: HashMap<String, Arc<Vec<Arc<dyn Plugin>>>> = current.proxy_plugins.clone();

        // Remove deleted proxies
        for id in removed_proxy_ids {
            new_map.remove(id);
        }

        // Rebuild only the affected proxies' plugin lists
        for proxy in &config.proxies {
            if !proxy_ids_to_rebuild.contains(&proxy.id) {
                continue;
            }

            let mut merged: Vec<Arc<dyn Plugin>> = new_globals.as_ref().clone();
            let global_ptrs: HashSet<usize> = merged
                .iter()
                .map(|p| Arc::as_ptr(p) as *const () as usize)
                .collect();

            let proxy_plugin_ids: HashSet<&str> = proxy
                .plugins
                .iter()
                .map(|a| a.plugin_config_id.as_str())
                .collect();

            if let Some(scoped_configs) = proxy_scoped_configs.get(proxy.id.as_str()) {
                for pc in scoped_configs {
                    if proxy_plugin_ids.contains(pc.id.as_str()) {
                        match try_create_plugin(pc, &self.http_client) {
                            Ok(Some(plugin)) => {
                                // Detect when an auto-emitted plugin instance
                                // (Istio VirtualService translator helpers) is
                                // about to shadow an operator-configured global
                                // of the same name. The operator's global will
                                // not apply to this proxy, which may surprise
                                // operators who expected the global's static
                                // rules to also run for VS-translated routes.
                                // Emit a warn so the silent shadowing is at
                                // least operator-visible.
                                if pc.id.starts_with("__istio_vs_") {
                                    let shadowed = merged.iter().any(|p| {
                                        p.name() == plugin.name()
                                            && global_ptrs
                                                .contains(&(Arc::as_ptr(p) as *const () as usize))
                                    });
                                    if shadowed {
                                        warn!(
                                            proxy = %proxy.id,
                                            plugin = plugin.name(),
                                            auto_emit_id = %pc.id,
                                            "Istio VirtualService translator auto-emitted a proxy-scoped {} instance to consume route-level header transforms; this shadows the operator-configured global {} on this proxy. Move the global's rules to the VirtualService or pre-create a proxy-scoped instance with the merged ruleset to retain both behaviors.",
                                            plugin.name(),
                                            plugin.name(),
                                        );
                                    }
                                }
                                // Remove only GLOBAL plugins of the same name.
                                remove_shadowed_global_plugin(
                                    &mut merged,
                                    &global_ptrs,
                                    plugin.name(),
                                );
                                merged.push(plugin);
                            }
                            Ok(None) => {
                                remove_shadowed_global_plugin(
                                    &mut merged,
                                    &global_ptrs,
                                    &pc.plugin_name,
                                );
                            }
                            Err(e) => {
                                error!(proxy_id = %proxy.id, "Config reload: {}", e);
                                plugin_errors.push(format!("proxy_id={}: {}", proxy.id, e));
                            }
                        }
                    }
                }
            }

            // Resolve proxy_group-scoped plugins via the proxy's association list
            for assoc in &proxy.plugins {
                if let Some(pc) = proxy_group_configs.get(assoc.plugin_config_id.as_str()) {
                    if let Some(existing) = group_plugin_instances.get(pc.id.as_str()) {
                        let plugin = Arc::clone(&existing.plugin);
                        remove_shadowed_global_plugin(&mut merged, &global_ptrs, plugin.name());
                        merged.push(plugin);
                    } else {
                        match try_create_plugin(pc, &self.http_client) {
                            Ok(Some(plugin)) => {
                                group_plugin_instances.insert(
                                    pc.id.clone(),
                                    ProxyGroupPluginInstance {
                                        plugin: Arc::clone(&plugin),
                                        config: (*pc).clone(),
                                    },
                                );
                                remove_shadowed_global_plugin(
                                    &mut merged,
                                    &global_ptrs,
                                    plugin.name(),
                                );
                                merged.push(plugin);
                            }
                            Ok(None) => {
                                remove_shadowed_global_plugin(
                                    &mut merged,
                                    &global_ptrs,
                                    &pc.plugin_name,
                                );
                            }
                            Err(e) => {
                                error!(
                                    proxy_id = %proxy.id,
                                    plugin_config_id = %pc.id,
                                    "Config reload: {}",
                                    e
                                );
                                plugin_errors.push(format!("proxy_id={}: {}", proxy.id, e));
                            }
                        }
                    }
                }
            }

            merged.sort_by_key(|p| p.priority());
            new_map.insert(proxy.id.clone(), Arc::new(merged));
        }

        // Update buffering maps for changed proxies
        let mut new_buffering: BufferingMap = current.requires_buffering.clone();
        let mut new_req_buffering: RequestBufferingMap = current.requires_request_buffering.clone();
        let mut new_ws_frame: WsFrameMap = current.requires_ws_frame.clone();
        for id in removed_proxy_ids {
            new_buffering.remove(id);
            new_req_buffering.remove(id);
            new_ws_frame.remove(id);
        }
        for proxy in &config.proxies {
            if proxy_ids_to_rebuild.contains(&proxy.id)
                && let Some(plugins) = new_map.get(&proxy.id)
            {
                new_buffering.insert(
                    proxy.id.clone(),
                    plugins.iter().any(|p| p.requires_response_body_buffering()),
                );
                new_req_buffering.insert(
                    proxy.id.clone(),
                    plugins.iter().any(|p| p.requires_request_body_buffering()),
                );
                new_ws_frame.insert(
                    proxy.id.clone(),
                    plugins.iter().any(|p| p.requires_ws_frame_hooks()),
                );
            }
        }

        // Reject the delta if any enabled plugin failed validation or could
        // not be resolved. The staged generation has not been published, so
        // callers keep serving the last known-good cache.
        // When `rebuild_globals` was true, we opened a registry reload
        // bracket above — abort it so the process-global named-schema
        // registry doesn't get mutated by a config that's being rejected.
        if !plugin_errors.is_empty() {
            if rebuild_globals {
                crate::plugins::utils::log_schema::registry::abort_reload();
            }
            return Err(format!(
                "Config reload rejected: {} plugin config(s) failed validation: {}",
                plugin_errors.len(),
                plugin_errors.join("; ")
            ));
        }

        if let Err(error) = start_background_tasks(&new_map, &new_globals) {
            if rebuild_globals {
                crate::plugins::utils::log_schema::registry::abort_reload();
            }
            return Err(format!("Config reload rejected: {error}"));
        }

        // Rebuild protocol snapshot (plugins + phase data) for changed proxies.
        // Clone-and-patch from the current snapshot so unchanged proxies are preserved.
        let mut new_proxy_proto = current.protocol_snapshot.proxy.clone();
        for id in removed_proxy_ids {
            new_proxy_proto.remove(id);
        }
        for proxy in &config.proxies {
            if proxy_ids_to_rebuild.contains(&proxy.id)
                && let Some(plugins) = new_map.get(&proxy.id)
            {
                let mut inner = HashMap::with_capacity(ALL_PROXY_PROTOCOLS.len());
                for &proto in &ALL_PROXY_PROTOCOLS {
                    inner.insert(proto, build_protocol_entry(plugins, proto));
                }
                new_proxy_proto.insert(proxy.id.clone(), inner);
            }
        }
        let new_global_proto = if rebuild_globals {
            let mut g = HashMap::with_capacity(ALL_PROXY_PROTOCOLS.len());
            for &proto in &ALL_PROXY_PROTOCOLS {
                g.insert(proto, build_protocol_entry(&new_globals, proto));
            }
            g
        } else {
            current.protocol_snapshot.global.clone()
        };

        let new_global_requires_buffering = if rebuild_globals {
            new_globals
                .iter()
                .any(|p| p.requires_response_body_buffering())
        } else {
            current.global_requires_buffering
        };
        let new_global_requires_request_buffering = if rebuild_globals {
            new_globals
                .iter()
                .any(|p| p.requires_request_body_buffering())
        } else {
            current.global_requires_request_buffering
        };
        let new_global_requires_ws_frame = if rebuild_globals {
            new_globals.iter().any(|p| p.requires_ws_frame_hooks())
        } else {
            current.global_requires_ws_frame
        };

        // Delta build succeeded. If a registry reload bracket was opened
        // above (rebuild_globals == true), promote the staged named
        // schemas now — pairs with the `begin_reload` at the top.
        if rebuild_globals {
            crate::plugins::utils::log_schema::registry::commit_reload();
        }

        Ok(Arc::new(PluginCacheInner::new(
            new_map,
            new_globals,
            new_buffering,
            new_global_requires_buffering,
            new_req_buffering,
            new_global_requires_request_buffering,
            ProtocolSnapshot {
                proxy: new_proxy_proto,
                global: new_global_proto,
            },
            new_ws_frame,
            new_global_requires_ws_frame,
            group_plugin_instances,
        )))
    }

    pub fn apply_delta(
        &self,
        config: &GatewayConfig,
        proxy_ids_to_rebuild: &HashSet<String>,
        removed_proxy_ids: &[String],
        rebuild_globals: bool,
    ) -> Result<(), String> {
        let current = self.inner.load();
        let inner = self.build_delta_inner(
            &current,
            config,
            proxy_ids_to_rebuild,
            removed_proxy_ids,
            rebuild_globals,
        )?;

        // Single atomic swap — readers see old or new, never a partial state.
        self.store_inner(Arc::clone(&inner));

        // Clean up JWKS cache entries (and their background refresh tasks)
        // after commit so a rejected staged cache never prunes the live set.
        Self::retain_active_uris_for_inner(&inner);

        Ok(())
    }

    /// Get the pre-resolved plugins for a proxy. Lock-free O(1) lookup.
    ///
    /// Returns an Arc to the cached plugin Vec — zero allocation per request.
    /// Callers iterate by reference; no Vec clone needed.
    #[allow(dead_code)] // Used by tests for protocol-agnostic plugin inspection
    pub fn get_plugins(&self, proxy_id: &str) -> Arc<Vec<Arc<dyn Plugin>>> {
        let inner = self.inner.load();
        inner.get_plugins(proxy_id)
    }

    /// Get pre-resolved plugins for a proxy filtered by protocol. Lock-free O(1) lookup.
    ///
    /// Returns only plugins that declare support for the given protocol.
    /// Pre-computed at config reload time — zero filtering cost per request.
    pub fn get_plugins_for_protocol(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> Arc<Vec<Arc<dyn Plugin>>> {
        let inner = self.inner.load();
        inner.get_plugins_for_protocol(proxy_id, protocol)
    }

    /// Get pre-computed auth plugins for a proxy+protocol. Lock-free O(1) lookup.
    /// Returns only plugins where `is_auth_plugin() == true`, pre-filtered at
    /// config reload time — eliminates the per-request `filter().collect()` Vec allocation.
    ///
    /// Standalone accessor: each call loads the cache independently. Request
    /// paths that need multiple plugin-cache values should use
    /// `request_view()` for cross-accessor generation consistency.
    #[allow(dead_code)] // Retained standalone API; hot request paths use request_view().
    pub fn get_auth_plugins(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> Arc<Vec<Arc<dyn Plugin>>> {
        let inner = self.inner.load();
        inner.get_auth_plugins(proxy_id, protocol)
    }

    /// Get pre-computed capability bitset for a proxy+protocol. Lock-free O(1) lookup.
    /// Replaces per-request `plugins.iter().any(|p| p.some_flag())` scans.
    ///
    /// Standalone accessor: each call loads the cache independently. Request
    /// paths that need multiple plugin-cache values should use
    /// `request_view()` for cross-accessor generation consistency.
    #[allow(dead_code)] // Retained standalone API; hot request paths use request_view().
    pub fn get_capabilities(&self, proxy_id: &str, protocol: ProxyProtocol) -> PluginCapabilities {
        let inner = self.inner.load();
        inner.get_capabilities(proxy_id, protocol)
    }

    /// Check whether any plugin for this proxy requires response body buffering.
    /// Pre-computed at config load time — O(1) lookup instead of per-request iteration.
    ///
    /// Standalone accessor: each call loads the cache independently. Request
    /// paths that need multiple plugin-cache values should use
    /// `request_view()` for cross-accessor generation consistency.
    #[allow(dead_code)] // Retained standalone API; hot request paths use request_view().
    pub fn requires_response_body_buffering(&self, proxy_id: &str) -> bool {
        let inner = self.inner.load();
        inner.requires_response_body_buffering(proxy_id)
    }

    /// Check whether any plugin for this proxy may require request body
    /// buffering. This is a config-time upper bound used to skip per-request
    /// plugin scans entirely when body-aware plugins are absent.
    /// Pre-computed at config load time — O(1) lookup instead of per-request iteration.
    pub fn requires_request_body_buffering(&self, proxy_id: &str) -> bool {
        let inner = self.inner.load();
        inner.requires_request_body_buffering(proxy_id)
    }

    /// Check whether any plugin for this proxy requires per-frame WebSocket hooks.
    /// When false, the WebSocket frame forwarding loop skips plugins entirely (zero overhead).
    /// Pre-computed at config load time — O(1) lookup instead of per-request iteration.
    ///
    /// Standalone accessor: each call loads the cache independently. Request
    /// paths that need multiple plugin-cache values should use
    /// `request_view()` for cross-accessor generation consistency.
    #[allow(dead_code)] // Retained standalone API; hot request paths use request_view().
    pub fn requires_ws_frame_hooks(&self, proxy_id: &str) -> bool {
        let inner = self.inner.load();
        inner.requires_ws_frame_hooks(proxy_id)
    }

    /// Collect all hostnames that plugins will send traffic to.
    ///
    /// Iterates all cached plugin instances (global + per-proxy) and calls
    /// `warmup_hostnames()` on each. Returns deduplicated hostnames suitable
    /// for feeding into `DnsCache::warmup()`.
    pub fn collect_warmup_hostnames(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        let inner = self.inner.load();

        // Collect from global plugins
        for plugin in inner.global_plugins.iter() {
            for host in plugin.warmup_hostnames() {
                if seen.insert(host.clone()) {
                    result.push(host);
                }
            }
        }

        // Collect from per-proxy plugins
        for plugins in inner.proxy_plugins.values() {
            for plugin in plugins.iter() {
                for host in plugin.warmup_hostnames() {
                    if seen.insert(host.clone()) {
                        result.push(host);
                    }
                }
            }
        }

        result
    }

    /// Total number of tracked rate-limiter keys across all plugin instances.
    pub fn total_rate_limiter_keys(&self) -> usize {
        let mut total = 0usize;
        let mut seen = std::collections::HashSet::new();
        let inner = self.inner.load();

        // Count from global plugins
        for plugin in inner.global_plugins.iter() {
            let ptr = Arc::as_ptr(plugin) as *const () as usize;
            if seen.insert(ptr)
                && let Some(count) = plugin.tracked_keys_count()
            {
                total += count;
            }
        }

        // Count from per-proxy plugins (deduplicate by pointer identity)
        for plugins in inner.proxy_plugins.values() {
            for plugin in plugins.iter() {
                let ptr = Arc::as_ptr(plugin) as *const () as usize;
                if seen.insert(ptr)
                    && let Some(count) = plugin.tracked_keys_count()
                {
                    total += count;
                }
            }
        }

        total
    }

    /// Number of proxy entries in the cache (for testing).
    #[allow(dead_code)]
    pub fn proxy_count(&self) -> usize {
        self.inner.load().proxy_plugins.len()
    }

    #[allow(clippy::type_complexity)]
    fn build_cache(
        config: &GatewayConfig,
        http_client: &PluginHttpClient,
    ) -> Result<
        (
            ProxyPluginMap,
            PluginList,
            BufferingMap,
            bool,
            RequestBufferingMap,
            bool,
            WsFrameMap,
            bool,
            ProxyGroupInstanceMap,
        ),
        String,
    > {
        // Step 1: Create all enabled global plugins (shared across proxies)
        let mut global_plugins: Vec<Arc<dyn Plugin>> = Vec::new();

        // Pre-index proxy-scoped plugin configs by proxy_id for O(1) lookup
        // instead of scanning all plugin_configs for every proxy (O(P×C) → O(P+C)).
        let mut proxy_scoped_configs: HashMap<&str, Vec<&crate::config::types::PluginConfig>> =
            HashMap::new();

        // Collect all enabled-plugin construction errors to report before bailing.
        let mut plugin_errors: Vec<String> = Vec::new();

        // Pre-index proxy_group-scoped plugin configs by config ID for shared
        // instance creation. A single ProxyGroup plugin instance is shared across
        // all proxies that reference it, so stateful plugins (e.g., rate_limiting)
        // share counters across the group.
        let mut proxy_group_configs: HashMap<&str, &crate::config::types::PluginConfig> =
            HashMap::new();

        // First pass: stage the named-schema registry from
        // `transaction_log_schema` global plugins so subsequent plugins
        // can resolve `schema_ref:` against the new state via the
        // reload thread's staging-visibility (see `registry::lookup_named`).
        // The bracket is left OPEN here — `commit_reload` only runs after
        // the rest of the plugin-cache build succeeds; `abort_reload`
        // runs if any plugin fails validation, so the process-global
        // registry stays atomically tied to the cache.
        crate::plugins::utils::log_schema::registry::begin_reload();
        for pc in &config.plugin_configs {
            if !pc.enabled || pc.scope != PluginScope::Global {
                continue;
            }
            if pc.plugin_name != "transaction_log_schema" {
                continue;
            }
            match try_create_plugin(pc, http_client) {
                Ok(Some(plugin)) => global_plugins.push(plugin),
                Ok(None) => {}
                Err(e) => plugin_errors.push(e),
            }
        }

        // Second pass: everything else, including other globals,
        // proxy-scoped, and proxy_group-scoped configs.
        for pc in &config.plugin_configs {
            if !pc.enabled {
                continue;
            }
            if pc.plugin_name == "transaction_log_schema" {
                continue; // already constructed above
            }
            if pc.scope == PluginScope::Global {
                match try_create_plugin(pc, http_client) {
                    Ok(Some(plugin)) => global_plugins.push(plugin),
                    Ok(None) => {}
                    Err(e) => plugin_errors.push(e),
                }
            } else if pc.scope == PluginScope::Proxy
                && let Some(ref proxy_id) = pc.proxy_id
            {
                proxy_scoped_configs
                    .entry(proxy_id.as_str())
                    .or_default()
                    .push(pc);
            } else if pc.scope == PluginScope::ProxyGroup {
                proxy_group_configs.insert(pc.id.as_str(), pc);
            }
        }

        // Lazily create shared ProxyGroup plugin instances (created on first
        // reference, then Arc-cloned for subsequent proxies in the group).
        let mut group_plugin_instances: ProxyGroupInstanceMap = HashMap::new();

        // Step 2: For each proxy, resolve its full plugin list
        // (global + proxy-scoped, with proxy overriding global of same name)
        let mut proxy_map: HashMap<String, Arc<Vec<Arc<dyn Plugin>>>> =
            HashMap::with_capacity(config.proxies.len());
        let mut buffering_map: BufferingMap = HashMap::with_capacity(config.proxies.len());
        let mut req_buffering_map: RequestBufferingMap =
            HashMap::with_capacity(config.proxies.len());
        let mut ws_frame_map: WsFrameMap = HashMap::with_capacity(config.proxies.len());

        for proxy in &config.proxies {
            // Start with global plugins
            let mut merged = global_plugins.clone(); // Clones Arcs, not instances
            // Track which Arc pointers came from the global list so we can
            // selectively remove only globals when a proxy-scoped plugin of
            // the same name is added (preserving other proxy-scoped instances).
            let global_ptrs: HashSet<usize> = merged
                .iter()
                .map(|p| Arc::as_ptr(p) as *const () as usize)
                .collect();

            // Collect which plugin config IDs this proxy explicitly references
            let proxy_plugin_ids: std::collections::HashSet<&str> = proxy
                .plugins
                .iter()
                .map(|a| a.plugin_config_id.as_str())
                .collect();

            // Resolve proxy-scoped plugins indexed by proxy_id (O(plugins_per_proxy))
            if let Some(scoped_configs) = proxy_scoped_configs.get(proxy.id.as_str()) {
                for pc in scoped_configs {
                    if proxy_plugin_ids.contains(pc.id.as_str()) {
                        match try_create_plugin(pc, http_client) {
                            Ok(Some(plugin)) => {
                                // Remove only GLOBAL plugins of the same name —
                                // other proxy-scoped instances are preserved,
                                // allowing multiple instances of the same plugin type.
                                remove_shadowed_global_plugin(
                                    &mut merged,
                                    &global_ptrs,
                                    plugin.name(),
                                );
                                merged.push(plugin);
                            }
                            Ok(None) => {
                                remove_shadowed_global_plugin(
                                    &mut merged,
                                    &global_ptrs,
                                    &pc.plugin_name,
                                );
                            }
                            Err(e) => plugin_errors.push(format!("proxy_id={}: {}", proxy.id, e)),
                        }
                    }
                }
            }

            // Resolve proxy_group-scoped plugins via the proxy's association list.
            // Shared Arc instances are reused across all proxies in the group.
            for assoc in &proxy.plugins {
                if let Some(pc) = proxy_group_configs.get(assoc.plugin_config_id.as_str()) {
                    if let Some(existing) = group_plugin_instances.get(pc.id.as_str()) {
                        // Reuse the shared instance (Arc::clone is ~5ns)
                        let plugin = Arc::clone(&existing.plugin);
                        remove_shadowed_global_plugin(&mut merged, &global_ptrs, plugin.name());
                        merged.push(plugin);
                    } else {
                        // First proxy to reference this group plugin — create the instance
                        match try_create_plugin(pc, http_client) {
                            Ok(Some(plugin)) => {
                                group_plugin_instances.insert(
                                    pc.id.clone(),
                                    ProxyGroupPluginInstance {
                                        plugin: Arc::clone(&plugin),
                                        config: (*pc).clone(),
                                    },
                                );
                                remove_shadowed_global_plugin(
                                    &mut merged,
                                    &global_ptrs,
                                    plugin.name(),
                                );
                                merged.push(plugin);
                            }
                            Ok(None) => {
                                remove_shadowed_global_plugin(
                                    &mut merged,
                                    &global_ptrs,
                                    &pc.plugin_name,
                                );
                            }
                            Err(e) => plugin_errors.push(format!("proxy_id={}: {}", proxy.id, e)),
                        }
                    }
                }
            }

            // Sort by priority so execution order is deterministic
            merged.sort_by_key(|p| p.priority());

            // Pre-compute whether any plugin requires response body buffering
            let needs_buffering = merged.iter().any(|p| p.requires_response_body_buffering());
            buffering_map.insert(proxy.id.clone(), needs_buffering);

            // Pre-compute whether any plugin may require request body buffering
            let needs_req_buffering = merged.iter().any(|p| p.requires_request_body_buffering());
            req_buffering_map.insert(proxy.id.clone(), needs_req_buffering);

            // Pre-compute whether any plugin requires per-frame WebSocket hooks
            let needs_ws_frame = merged.iter().any(|p| p.requires_ws_frame_hooks());
            ws_frame_map.insert(proxy.id.clone(), needs_ws_frame);

            proxy_map.insert(proxy.id.clone(), Arc::new(merged));
        }

        // If any enabled plugin failed validation or could not be resolved,
        // refuse to build the cache.
        // Abort the named-schema reload bracket so the process-global registry
        // is NOT mutated by a config that's being rejected — otherwise the
        // live PluginCache stays on the old plugins while the registry
        // already reflects the rejected reload's schemas.
        if !plugin_errors.is_empty() {
            crate::plugins::utils::log_schema::registry::abort_reload();
            for err in &plugin_errors {
                error!("{}", err);
            }
            return Err(format!(
                "Gateway startup aborted: {} plugin config(s) failed validation: {}",
                plugin_errors.len(),
                plugin_errors.join("; ")
            ));
        }

        if let Err(error) = start_background_tasks(&proxy_map, &global_plugins) {
            crate::plugins::utils::log_schema::registry::abort_reload();
            return Err(format!("Gateway startup aborted: {error}"));
        }

        // All plugins validated — promote the staged named schemas to live.
        // Pairs with the `begin_reload` at the start of this function.
        crate::plugins::utils::log_schema::registry::commit_reload();

        // Sort global fallback list too
        global_plugins.sort_by_key(|p| p.priority());
        let global_needs_buffering = global_plugins
            .iter()
            .any(|p| p.requires_response_body_buffering());
        let global_needs_req_buffering = global_plugins
            .iter()
            .any(|p| p.requires_request_body_buffering());
        let global_needs_ws_frame = global_plugins.iter().any(|p| p.requires_ws_frame_hooks());

        Ok((
            proxy_map,
            Arc::new(global_plugins),
            buffering_map,
            global_needs_buffering,
            req_buffering_map,
            global_needs_req_buffering,
            ws_frame_map,
            global_needs_ws_frame,
            group_plugin_instances,
        ))
    }
}
