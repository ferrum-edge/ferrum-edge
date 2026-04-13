//! Pre-resolved plugin cache for O(1) per-request plugin lookup.
//!
//! Plugins are created once at config load time — not per-request. This is
//! critical for stateful plugins (e.g., `rate_limiting`) whose internal DashMap
//! counters must persist across requests. Without caching, a fresh rate limiter
//! would be created per request and limits would never be enforced.
//!
//! Each proxy gets a merged plugin list: global plugins + proxy-scoped plugins,
//! sorted by priority. Pre-computed flags (`requires_response_body_buffering`,
//! `requires_request_body_buffering`, `requires_ws_frame_hooks`) enable O(1)
//! upper-bound decisions on the hot path instead of per-request plugin
//! iteration.
//!
//! Incremental updates via `apply_delta()` preserve unchanged proxy plugin
//! lists (including their stateful instances) and only rebuild affected proxies.

use arc_swap::ArcSwap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::config::types::{GatewayConfig, PluginScope};
use tracing::{error, warn};

use crate::config::types::PluginConfig;
use crate::plugins::utils::jwks_cache::retain_active_uris;
use crate::plugins::{Plugin, PluginHttpClient, ProxyProtocol, create_plugin_with_http_client};

// ---------------------------------------------------------------------------
// PriorityOverridePlugin — wraps any plugin with a user-specified priority
// ---------------------------------------------------------------------------

use crate::plugins::{
    PluginResult, RequestContext, StreamConnectionContext, StreamTransactionSummary,
    TransactionSummary, UdpDatagramContext, UdpDatagramVerdict, WebSocketFrameDirection,
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
    fn modifies_request_headers(&self) -> bool {
        self.inner.modifies_request_headers()
    }
    fn modifies_request_body(&self) -> bool {
        self.inner.modifies_request_body()
    }
    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.inner.requires_request_body_before_before_proxy()
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
    fn applies_after_proxy_on_reject(&self) -> bool {
        self.inner.applies_after_proxy_on_reject()
    }
    fn requires_response_body_buffering(&self) -> bool {
        self.inner.requires_response_body_buffering()
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
    async fn on_final_request_body(
        &self,
        headers: &std::collections::HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        self.inner.on_final_request_body(headers, body).await
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
    async fn log(&self, summary: &TransactionSummary) {
        self.inner.log(summary).await;
    }
    fn is_auth_plugin(&self) -> bool {
        self.inner.is_auth_plugin()
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
    fn requires_udp_datagram_hooks(&self) -> bool {
        self.inner.requires_udp_datagram_hooks()
    }
    async fn on_udp_datagram(&self, ctx: &UdpDatagramContext) -> UdpDatagramVerdict {
        self.inner.on_udp_datagram(ctx).await
    }
    fn active_jwks_uris(&self) -> Vec<String> {
        self.inner.active_jwks_uris()
    }
}

/// Try to create a plugin, logging validation errors. Applies
/// `priority_override` from the plugin config when set.
///
/// For security-critical plugins (auth, access_control, ip_restriction),
/// validation errors are propagated as `Err` so the gateway can refuse to start.
/// For non-security plugins, validation errors are logged and the plugin is skipped.
fn try_create_plugin(
    pc: &PluginConfig,
    http_client: &PluginHttpClient,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    match create_plugin_with_http_client(&pc.plugin_name, &pc.config, http_client.clone()) {
        Ok(Some(plugin)) => {
            if let Some(priority) = pc.priority_override {
                Ok(Some(Arc::new(PriorityOverridePlugin {
                    inner: plugin,
                    priority,
                })))
            } else {
                Ok(Some(plugin))
            }
        }
        Ok(None) => {
            warn!(
                "Unknown plugin '{}' (plugin_config_id={}), skipping",
                pc.plugin_name, pc.id
            );
            Ok(None)
        }
        Err(e) => {
            if crate::plugins::is_security_plugin(&pc.plugin_name) {
                error!(
                    "FATAL: Security plugin '{}' (plugin_config_id={}) config validation failed: {}",
                    pc.plugin_name, pc.id, e
                );
                Err(format!(
                    "Security plugin '{}' (plugin_config_id={}) config validation failed: {}",
                    pc.plugin_name, pc.id, e
                ))
            } else {
                error!(
                    "Plugin '{}' (plugin_config_id={}) config validation failed: {} — skipping",
                    pc.plugin_name, pc.id, e
                );
                Ok(None)
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

// ---------------------------------------------------------------------------
// Per-protocol phase data — precomputed at config reload time
// ---------------------------------------------------------------------------

/// Bitflags for per-protocol plugin capability checks. Avoids per-request
/// `plugins.iter().any(|p| p.some_flag())` scans on the hot path.
#[derive(Clone, Copy, Default)]
pub struct PluginCapabilities(u8);

impl PluginCapabilities {
    pub const HAS_AUTH_PLUGINS: u8 = 1 << 0;
    pub const MODIFIES_REQUEST_HEADERS: u8 = 1 << 1;
    pub const MODIFIES_REQUEST_BODY: u8 = 1 << 2;
    pub const HAS_BODY_BEFORE_BEFORE_PROXY: u8 = 1 << 3;
    pub const NEEDS_REQUEST_BODY_BYTES: u8 = 1 << 4;

    #[inline(always)]
    pub fn has(self, flag: u8) -> bool {
        self.0 & flag != 0
    }
}

/// Pre-computed per-protocol plugin phase data for a single proxy.
/// Built at config reload time so the hot path does zero filtering or allocation.
#[derive(Clone)]
pub struct PluginPhaseData {
    /// Auth plugins only (pre-filtered from the protocol plugin list).
    pub auth_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    /// Capability bitset for fast boolean checks.
    pub capabilities: PluginCapabilities,
}

/// Build `PluginPhaseData` from a protocol-filtered plugin list.
fn build_phase_data(plugins: &[Arc<dyn Plugin>]) -> PluginPhaseData {
    let mut caps = 0u8;
    let mut auth = Vec::new();
    for p in plugins {
        if p.is_auth_plugin() {
            caps |= PluginCapabilities::HAS_AUTH_PLUGINS;
            auth.push(Arc::clone(p));
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
        if p.needs_request_body_bytes() {
            caps |= PluginCapabilities::NEEDS_REQUEST_BODY_BYTES;
        }
    }
    PluginPhaseData {
        auth_plugins: Arc::new(auth),
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
fn collect_active_jwks_uris(
    proxy_map: &ProxyPluginMap,
    globals: &[Arc<dyn Plugin>],
) -> HashSet<String> {
    let mut uris = HashSet::new();
    for plugins in proxy_map.values() {
        for plugin in plugins.iter() {
            uris.extend(plugin.active_jwks_uris());
        }
    }
    for plugin in globals {
        uris.extend(plugin.active_jwks_uris());
    }
    uris
}

/// Pre-resolved plugin cache that avoids per-request plugin creation.
///
/// Plugins are created once at config load time and cached per proxy_id.
/// This is critical for stateful plugins like `rate_limiting` whose internal
/// DashMap state must persist across requests. Without caching, a new
/// rate limiter is created per request and limits are never enforced.
///
/// Rebuilt atomically via ArcSwap on config changes — reads are lock-free.
pub struct PluginCache {
    /// proxy_id → pre-resolved plugin list (global + proxy-scoped, merged).
    /// Wrapped in Arc<Vec<...>> so `get_plugins` returns a cheap Arc clone
    /// instead of cloning the entire Vec on every request.
    proxy_plugins: ArcSwap<ProxyPluginMap>,
    /// Fallback: global plugins only (for proxies with no scoped overrides)
    global_plugins: ArcSwap<PluginList>,
    /// Pre-computed: does any plugin for this proxy require response body buffering?
    /// Avoids per-request O(n) scan of plugins at request time.
    requires_buffering: ArcSwap<BufferingMap>,
    /// Whether global-only plugins require response body buffering (fallback).
    global_requires_buffering: ArcSwap<bool>,
    /// Pre-computed: does any plugin for this proxy ever require request body
    /// buffering? When false, request bodies can be streamed directly to the
    /// backend without further per-request checks.
    requires_request_buffering: ArcSwap<RequestBufferingMap>,
    /// Whether global-only plugins require request body buffering (fallback).
    global_requires_request_buffering: ArcSwap<bool>,
    /// Pre-computed per-protocol plugin lists + phase data (auth plugin lists,
    /// capability bitsets), bundled in a single ArcSwap for atomic swap.
    /// Ensures a request always reads a consistent (plugin list, phase data)
    /// pair from the same config generation — no mixed-generation reads.
    protocol_snapshot: ArcSwap<ProtocolSnapshot>,
    /// Pre-computed: does any plugin for this proxy require per-frame WebSocket hooks?
    /// When false, the WebSocket frame forwarding loop skips plugins entirely (zero overhead).
    requires_ws_frame: ArcSwap<WsFrameMap>,
    /// Whether global-only plugins require per-frame WebSocket hooks (fallback).
    global_requires_ws_frame: ArcSwap<bool>,
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
        let (
            proxy_map,
            globals,
            buffering_map,
            global_needs_buffering,
            req_buffering_map,
            global_needs_req_buffering,
            ws_frame_map,
            global_needs_ws_frame,
        ) = Self::build_cache(config, &http_client)?;
        let snapshot = build_protocol_snapshot(&proxy_map, &globals);
        Ok(Self {
            proxy_plugins: ArcSwap::new(Arc::new(proxy_map)),
            global_plugins: ArcSwap::new(Arc::new(globals)),
            requires_buffering: ArcSwap::new(Arc::new(buffering_map)),
            global_requires_buffering: ArcSwap::new(Arc::new(global_needs_buffering)),
            requires_request_buffering: ArcSwap::new(Arc::new(req_buffering_map)),
            global_requires_request_buffering: ArcSwap::new(Arc::new(global_needs_req_buffering)),
            protocol_snapshot: ArcSwap::new(Arc::new(snapshot)),
            requires_ws_frame: ArcSwap::new(Arc::new(ws_frame_map)),
            global_requires_ws_frame: ArcSwap::new(Arc::new(global_needs_ws_frame)),
            http_client,
        })
    }

    /// Atomically rebuild the cache when config changes.
    /// Old plugin instances (including rate limiter state) are dropped
    /// only after all in-flight requests using them complete.
    ///
    /// Returns `Err` if a security-critical plugin fails validation.
    pub fn rebuild(&self, config: &GatewayConfig) -> Result<(), String> {
        let (
            proxy_map,
            globals,
            buffering_map,
            global_needs_buffering,
            req_buffering_map,
            global_needs_req_buffering,
            ws_frame_map,
            global_needs_ws_frame,
        ) = Self::build_cache(config, &self.http_client)?;
        let snapshot = build_protocol_snapshot(&proxy_map, &globals);

        // Clean up JWKS cache entries (and their background refresh tasks)
        // for URIs no longer referenced by any active jwks_auth plugin.
        let active_uris = collect_active_jwks_uris(&proxy_map, &globals);
        retain_active_uris(&active_uris);

        self.proxy_plugins.store(Arc::new(proxy_map));
        self.global_plugins.store(Arc::new(globals));
        self.requires_buffering.store(Arc::new(buffering_map));
        self.global_requires_buffering
            .store(Arc::new(global_needs_buffering));
        self.requires_request_buffering
            .store(Arc::new(req_buffering_map));
        self.global_requires_request_buffering
            .store(Arc::new(global_needs_req_buffering));
        self.protocol_snapshot.store(Arc::new(snapshot));
        self.requires_ws_frame.store(Arc::new(ws_frame_map));
        self.global_requires_ws_frame
            .store(Arc::new(global_needs_ws_frame));
        Ok(())
    }

    /// Incrementally update the plugin cache, only rebuilding plugins for
    /// proxies identified in `proxy_ids_to_rebuild`. All other proxy plugin
    /// lists — including their stateful plugin instances (rate limiters, etc.)
    /// — are preserved unchanged.
    ///
    /// Also rebuilds global plugins if `rebuild_globals` is true (i.e., a
    /// global-scoped plugin config was added/modified/removed).
    /// Returns `Err` if a security-critical plugin fails validation during
    /// incremental update, matching the behavior of `rebuild()`.
    pub fn apply_delta(
        &self,
        config: &GatewayConfig,
        proxy_ids_to_rebuild: &HashSet<String>,
        removed_proxy_ids: &[String],
        rebuild_globals: bool,
    ) -> Result<(), String> {
        let mut security_errors: Vec<String> = Vec::new();

        // Load the current state — we'll clone-and-patch it
        let current_map = self.proxy_plugins.load();
        let current_globals = self.global_plugins.load();

        // Rebuild globals if any global plugin config changed
        let new_globals = if rebuild_globals {
            let mut global_plugins: Vec<Arc<dyn Plugin>> = Vec::new();
            for pc in &config.plugin_configs {
                if !pc.enabled {
                    continue;
                }
                if pc.scope == PluginScope::Global {
                    match try_create_plugin(pc, &self.http_client) {
                        Ok(Some(plugin)) => global_plugins.push(plugin),
                        Ok(None) => {}
                        Err(e) => {
                            error!("Config reload: {}", e);
                            security_errors.push(e);
                        }
                    }
                }
            }
            global_plugins.sort_by_key(|p| p.priority());
            Arc::new(global_plugins)
        } else {
            Arc::clone(current_globals.as_ref())
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

        // Shared ProxyGroup plugin instances (created on first reference, reused)
        let mut group_plugin_instances: HashMap<&str, Arc<dyn Plugin>> = HashMap::new();

        // Clone the current map and patch it
        let mut new_map: HashMap<String, Arc<Vec<Arc<dyn Plugin>>>> = current_map.as_ref().clone();

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
                                // Remove only GLOBAL plugins of the same name
                                merged.retain(|p| {
                                    p.name() != plugin.name()
                                        || !global_ptrs
                                            .contains(&(Arc::as_ptr(p) as *const () as usize))
                                });
                                merged.push(plugin);
                            }
                            Ok(None) => {}
                            Err(e) => {
                                error!("Config reload: {}", e);
                                security_errors.push(e);
                            }
                        }
                    }
                }
            }

            // Resolve proxy_group-scoped plugins via the proxy's association list
            for assoc in &proxy.plugins {
                if let Some(pc) = proxy_group_configs.get(assoc.plugin_config_id.as_str()) {
                    if let Some(existing) = group_plugin_instances.get(pc.id.as_str()) {
                        let plugin = Arc::clone(existing);
                        merged.retain(|p| {
                            p.name() != plugin.name()
                                || !global_ptrs.contains(&(Arc::as_ptr(p) as *const () as usize))
                        });
                        merged.push(plugin);
                    } else {
                        match try_create_plugin(pc, &self.http_client) {
                            Ok(Some(plugin)) => {
                                group_plugin_instances.insert(pc.id.as_str(), Arc::clone(&plugin));
                                merged.retain(|p| {
                                    p.name() != plugin.name()
                                        || !global_ptrs
                                            .contains(&(Arc::as_ptr(p) as *const () as usize))
                                });
                                merged.push(plugin);
                            }
                            Ok(None) => {}
                            Err(e) => {
                                error!("Config reload: {}", e);
                                security_errors.push(e);
                            }
                        }
                    }
                }
            }

            merged.sort_by_key(|p| p.priority());
            new_map.insert(proxy.id.clone(), Arc::new(merged));
        }

        // Update buffering maps for changed proxies
        let mut new_buffering: BufferingMap = self.requires_buffering.load().as_ref().clone();
        let mut new_req_buffering: RequestBufferingMap =
            self.requires_request_buffering.load().as_ref().clone();
        let mut new_ws_frame: WsFrameMap = self.requires_ws_frame.load().as_ref().clone();
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

        // Reject the delta if any security plugin failed validation
        if !security_errors.is_empty() {
            return Err(format!(
                "Config reload rejected: {} security plugin(s) failed validation",
                security_errors.len()
            ));
        }

        // Clean up JWKS cache entries (and their background refresh tasks)
        // for URIs no longer referenced by any active jwks_auth plugin.
        let active_uris = collect_active_jwks_uris(&new_map, &new_globals);
        retain_active_uris(&active_uris);

        // Rebuild protocol snapshot (plugins + phase data) for changed proxies.
        // Clone-and-patch from the current snapshot so unchanged proxies are preserved.
        let current_snapshot = self.protocol_snapshot.load();
        let mut new_proxy_proto = current_snapshot.proxy.clone();
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
            current_snapshot.global.clone()
        };

        // Atomic swap — readers see old or new, never a partial state
        self.proxy_plugins.store(Arc::new(new_map));
        self.requires_buffering.store(Arc::new(new_buffering));
        self.requires_request_buffering
            .store(Arc::new(new_req_buffering));
        self.requires_ws_frame.store(Arc::new(new_ws_frame));
        self.protocol_snapshot.store(Arc::new(ProtocolSnapshot {
            proxy: new_proxy_proto,
            global: new_global_proto,
        }));
        if rebuild_globals {
            self.global_plugins.store(Arc::new(new_globals.clone()));
            self.global_requires_buffering.store(Arc::new(
                new_globals
                    .iter()
                    .any(|p| p.requires_response_body_buffering()),
            ));
            self.global_requires_request_buffering.store(Arc::new(
                new_globals
                    .iter()
                    .any(|p| p.requires_request_body_buffering()),
            ));
            self.global_requires_ws_frame.store(Arc::new(
                new_globals.iter().any(|p| p.requires_ws_frame_hooks()),
            ));
        }

        Ok(())
    }

    /// Get the pre-resolved plugins for a proxy. Lock-free O(1) lookup.
    ///
    /// Returns an Arc to the cached plugin Vec — zero allocation per request.
    /// Callers iterate by reference; no Vec clone needed.
    #[allow(dead_code)] // Used by tests for protocol-agnostic plugin inspection
    pub fn get_plugins(&self, proxy_id: &str) -> Arc<Vec<Arc<dyn Plugin>>> {
        let map = self.proxy_plugins.load();
        if let Some(plugins) = map.get(proxy_id) {
            Arc::clone(plugins)
        } else {
            // Fallback to global-only plugins
            let globals = self.global_plugins.load();
            Arc::clone(globals.as_ref())
        }
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
        let snap = self.protocol_snapshot.load();
        if let Some(entry) = snap
            .proxy
            .get(proxy_id)
            .and_then(|inner| inner.get(&protocol))
        {
            return Arc::clone(&entry.plugins);
        }
        if let Some(entry) = snap.global.get(&protocol) {
            Arc::clone(&entry.plugins)
        } else {
            Arc::new(Vec::new())
        }
    }

    /// Get pre-computed auth plugins for a proxy+protocol. Lock-free O(1) lookup.
    /// Returns only plugins where `is_auth_plugin() == true`, pre-filtered at
    /// config reload time — eliminates the per-request `filter().collect()` Vec allocation.
    ///
    /// Reads from the same `protocol_snapshot` ArcSwap as `get_plugins_for_protocol`
    /// and `get_capabilities`, ensuring all three always return data from the
    /// same config generation.
    pub fn get_auth_plugins(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> Arc<Vec<Arc<dyn Plugin>>> {
        let snap = self.protocol_snapshot.load();
        if let Some(entry) = snap
            .proxy
            .get(proxy_id)
            .and_then(|inner| inner.get(&protocol))
        {
            return Arc::clone(&entry.phase.auth_plugins);
        }
        if let Some(entry) = snap.global.get(&protocol) {
            Arc::clone(&entry.phase.auth_plugins)
        } else {
            Arc::new(Vec::new())
        }
    }

    /// Get pre-computed capability bitset for a proxy+protocol. Lock-free O(1) lookup.
    /// Replaces per-request `plugins.iter().any(|p| p.some_flag())` scans.
    pub fn get_capabilities(&self, proxy_id: &str, protocol: ProxyProtocol) -> PluginCapabilities {
        let snap = self.protocol_snapshot.load();
        if let Some(entry) = snap
            .proxy
            .get(proxy_id)
            .and_then(|inner| inner.get(&protocol))
        {
            return entry.phase.capabilities;
        }
        if let Some(entry) = snap.global.get(&protocol) {
            entry.phase.capabilities
        } else {
            PluginCapabilities::default()
        }
    }

    /// Check whether any plugin for this proxy requires response body buffering.
    /// Pre-computed at config load time — O(1) lookup instead of per-request iteration.
    pub fn requires_response_body_buffering(&self, proxy_id: &str) -> bool {
        let map = self.requires_buffering.load();
        if let Some(&needs) = map.get(proxy_id) {
            needs
        } else {
            // Fallback to global plugins' buffering requirement
            **self.global_requires_buffering.load()
        }
    }

    /// Check whether any plugin for this proxy may require request body
    /// buffering. This is a config-time upper bound used to skip per-request
    /// plugin scans entirely when body-aware plugins are absent.
    /// Pre-computed at config load time — O(1) lookup instead of per-request iteration.
    pub fn requires_request_body_buffering(&self, proxy_id: &str) -> bool {
        let map = self.requires_request_buffering.load();
        if let Some(&needs) = map.get(proxy_id) {
            needs
        } else {
            // Fallback to global plugins' request buffering requirement
            **self.global_requires_request_buffering.load()
        }
    }

    /// Check whether any plugin for this proxy requires per-frame WebSocket hooks.
    /// When false, the WebSocket frame forwarding loop skips plugins entirely (zero overhead).
    /// Pre-computed at config load time — O(1) lookup instead of per-request iteration.
    pub fn requires_ws_frame_hooks(&self, proxy_id: &str) -> bool {
        let map = self.requires_ws_frame.load();
        if let Some(&needs) = map.get(proxy_id) {
            needs
        } else {
            **self.global_requires_ws_frame.load()
        }
    }

    /// Collect all hostnames that plugins will send traffic to.
    ///
    /// Iterates all cached plugin instances (global + per-proxy) and calls
    /// `warmup_hostnames()` on each. Returns deduplicated hostnames suitable
    /// for feeding into `DnsCache::warmup()`.
    pub fn collect_warmup_hostnames(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();

        // Collect from global plugins
        let globals = self.global_plugins.load();
        for plugin in globals.as_ref().iter() {
            for host in plugin.warmup_hostnames() {
                if seen.insert(host.clone()) {
                    result.push(host);
                }
            }
        }

        // Collect from per-proxy plugins
        let proxy_map = self.proxy_plugins.load();
        for plugins in proxy_map.values() {
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

        // Count from global plugins
        let globals = self.global_plugins.load();
        for plugin in globals.as_ref().iter() {
            let ptr = Arc::as_ptr(plugin) as *const () as usize;
            if seen.insert(ptr)
                && let Some(count) = plugin.tracked_keys_count()
            {
                total += count;
            }
        }

        // Count from per-proxy plugins (deduplicate by pointer identity)
        let proxy_map = self.proxy_plugins.load();
        for plugins in proxy_map.values() {
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
        self.proxy_plugins.load().len()
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
        ),
        String,
    > {
        // Step 1: Create all enabled global plugins (shared across proxies)
        let mut global_plugins: Vec<Arc<dyn Plugin>> = Vec::new();

        // Pre-index proxy-scoped plugin configs by proxy_id for O(1) lookup
        // instead of scanning all plugin_configs for every proxy (O(P×C) → O(P+C)).
        let mut proxy_scoped_configs: HashMap<&str, Vec<&crate::config::types::PluginConfig>> =
            HashMap::new();

        // Collect all security plugin errors to report before bailing
        let mut security_errors: Vec<String> = Vec::new();

        // Pre-index proxy_group-scoped plugin configs by config ID for shared
        // instance creation. A single ProxyGroup plugin instance is shared across
        // all proxies that reference it, so stateful plugins (e.g., rate_limiting)
        // share counters across the group.
        let mut proxy_group_configs: HashMap<&str, &crate::config::types::PluginConfig> =
            HashMap::new();

        for pc in &config.plugin_configs {
            if !pc.enabled {
                continue;
            }
            if pc.scope == PluginScope::Global {
                match try_create_plugin(pc, http_client) {
                    Ok(Some(plugin)) => global_plugins.push(plugin),
                    Ok(None) => {}
                    Err(e) => security_errors.push(e),
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
        let mut group_plugin_instances: HashMap<&str, Arc<dyn Plugin>> = HashMap::new();

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
                                merged.retain(|p| {
                                    p.name() != plugin.name()
                                        || !global_ptrs
                                            .contains(&(Arc::as_ptr(p) as *const () as usize))
                                });
                                merged.push(plugin);
                            }
                            Ok(None) => {}
                            Err(e) => security_errors.push(e),
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
                        let plugin = Arc::clone(existing);
                        merged.retain(|p| {
                            p.name() != plugin.name()
                                || !global_ptrs.contains(&(Arc::as_ptr(p) as *const () as usize))
                        });
                        merged.push(plugin);
                    } else {
                        // First proxy to reference this group plugin — create the instance
                        match try_create_plugin(pc, http_client) {
                            Ok(Some(plugin)) => {
                                group_plugin_instances.insert(pc.id.as_str(), Arc::clone(&plugin));
                                merged.retain(|p| {
                                    p.name() != plugin.name()
                                        || !global_ptrs
                                            .contains(&(Arc::as_ptr(p) as *const () as usize))
                                });
                                merged.push(plugin);
                            }
                            Ok(None) => {}
                            Err(e) => security_errors.push(e),
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

        // If any security plugins failed validation, refuse to build the cache
        if !security_errors.is_empty() {
            for err in &security_errors {
                error!("{}", err);
            }
            return Err(format!(
                "Gateway startup aborted: {} security plugin(s) failed config validation",
                security_errors.len()
            ));
        }

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
        ))
    }
}
