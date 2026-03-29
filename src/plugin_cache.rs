use arc_swap::ArcSwap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::config::types::{GatewayConfig, PluginScope};
use tracing::{error, warn};

use crate::config::types::PluginConfig;
use crate::plugins::{Plugin, PluginHttpClient, ProxyProtocol, create_plugin_with_http_client};

/// Try to create a plugin, logging validation errors.
///
/// For security-critical plugins (auth, access_control, ip_restriction),
/// validation errors are propagated as `Err` so the gateway can refuse to start.
/// For non-security plugins, validation errors are logged and the plugin is skipped.
fn try_create_plugin(
    pc: &PluginConfig,
    http_client: &PluginHttpClient,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    match create_plugin_with_http_client(&pc.plugin_name, &pc.config, http_client.clone()) {
        Ok(Some(plugin)) => Ok(Some(plugin)),
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
/// Map from proxy_id to whether any plugin requires request body buffering
/// (i.e., modifies the request body before forwarding to the backend).
type RequestBufferingMap = HashMap<String, bool>;
/// Map from (proxy_id, protocol) to pre-filtered plugin list.
type ProtocolPluginMap = HashMap<(String, ProxyProtocol), PluginList>;

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

/// Build protocol-filtered plugin maps from the full plugin map + global fallback.
fn build_protocol_maps(
    proxy_map: &ProxyPluginMap,
    globals: &[Arc<dyn Plugin>],
) -> (ProtocolPluginMap, HashMap<ProxyProtocol, PluginList>) {
    let protocols = [
        ProxyProtocol::Http,
        ProxyProtocol::Grpc,
        ProxyProtocol::WebSocket,
        ProxyProtocol::Tcp,
        ProxyProtocol::Udp,
    ];

    let mut proto_map = HashMap::with_capacity(proxy_map.len() * protocols.len());
    for (proxy_id, plugins) in proxy_map {
        for &proto in &protocols {
            proto_map.insert(
                (proxy_id.clone(), proto),
                filter_for_protocol(plugins, proto),
            );
        }
    }

    let mut global_proto_map = HashMap::with_capacity(protocols.len());
    for &proto in &protocols {
        global_proto_map.insert(proto, filter_for_protocol(globals, proto));
    }

    (proto_map, global_proto_map)
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
    /// Pre-computed: does any plugin for this proxy modify the request body?
    /// When false, request bodies can be streamed directly to the backend
    /// without collecting into memory first.
    requires_request_buffering: ArcSwap<RequestBufferingMap>,
    /// Whether global-only plugins require request body buffering (fallback).
    global_requires_request_buffering: ArcSwap<bool>,
    /// Pre-computed per-protocol plugin lists: (proxy_id, protocol) → filtered plugins.
    /// Avoids per-request filtering on the hot path.
    protocol_plugins: ArcSwap<ProtocolPluginMap>,
    /// Per-protocol global plugin fallback lists.
    global_protocol_plugins: ArcSwap<HashMap<ProxyProtocol, PluginList>>,
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
        ) = Self::build_cache(config, &http_client)?;
        let (proto_map, global_proto_map) = build_protocol_maps(&proxy_map, &globals);
        Ok(Self {
            proxy_plugins: ArcSwap::new(Arc::new(proxy_map)),
            global_plugins: ArcSwap::new(Arc::new(globals)),
            requires_buffering: ArcSwap::new(Arc::new(buffering_map)),
            global_requires_buffering: ArcSwap::new(Arc::new(global_needs_buffering)),
            requires_request_buffering: ArcSwap::new(Arc::new(req_buffering_map)),
            global_requires_request_buffering: ArcSwap::new(Arc::new(global_needs_req_buffering)),
            protocol_plugins: ArcSwap::new(Arc::new(proto_map)),
            global_protocol_plugins: ArcSwap::new(Arc::new(global_proto_map)),
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
        ) = Self::build_cache(config, &self.http_client)?;
        let (proto_map, global_proto_map) = build_protocol_maps(&proxy_map, &globals);
        self.proxy_plugins.store(Arc::new(proxy_map));
        self.global_plugins.store(Arc::new(globals));
        self.requires_buffering.store(Arc::new(buffering_map));
        self.global_requires_buffering
            .store(Arc::new(global_needs_buffering));
        self.requires_request_buffering
            .store(Arc::new(req_buffering_map));
        self.global_requires_request_buffering
            .store(Arc::new(global_needs_req_buffering));
        self.protocol_plugins.store(Arc::new(proto_map));
        self.global_protocol_plugins
            .store(Arc::new(global_proto_map));
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
            }
        }

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

            if let Some(scoped_configs) = proxy_scoped_configs.get(proxy.id.as_str()) {
                let proxy_plugin_ids: HashSet<&str> = proxy
                    .plugins
                    .iter()
                    .map(|a| a.plugin_config_id.as_str())
                    .collect();

                for pc in scoped_configs {
                    if proxy_plugin_ids.contains(pc.id.as_str()) {
                        match try_create_plugin(pc, &self.http_client) {
                            Ok(Some(plugin)) => {
                                merged.retain(|p| p.name() != plugin.name());
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
        for id in removed_proxy_ids {
            new_buffering.remove(id);
            new_req_buffering.remove(id);
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
                    plugins.iter().any(|p| p.modifies_request_body()),
                );
            }
        }

        // Rebuild protocol-filtered maps for changed proxies
        let mut new_proto_map: ProtocolPluginMap = self.protocol_plugins.load().as_ref().clone();
        let protocols = [
            ProxyProtocol::Http,
            ProxyProtocol::Grpc,
            ProxyProtocol::WebSocket,
            ProxyProtocol::Tcp,
            ProxyProtocol::Udp,
        ];
        for id in removed_proxy_ids {
            for &proto in &protocols {
                new_proto_map.remove(&(id.clone(), proto));
            }
        }
        for proxy in &config.proxies {
            if proxy_ids_to_rebuild.contains(&proxy.id)
                && let Some(plugins) = new_map.get(&proxy.id)
            {
                for &proto in &protocols {
                    new_proto_map.insert(
                        (proxy.id.clone(), proto),
                        filter_for_protocol(plugins, proto),
                    );
                }
            }
        }

        // Reject the delta if any security plugin failed validation
        if !security_errors.is_empty() {
            return Err(format!(
                "Config reload rejected: {} security plugin(s) failed validation",
                security_errors.len()
            ));
        }

        // Atomic swap — readers see old or new, never a partial state
        self.proxy_plugins.store(Arc::new(new_map));
        self.requires_buffering.store(Arc::new(new_buffering));
        self.requires_request_buffering
            .store(Arc::new(new_req_buffering));
        self.protocol_plugins.store(Arc::new(new_proto_map));
        if rebuild_globals {
            self.global_plugins.store(Arc::new(new_globals.clone()));
            self.global_requires_buffering.store(Arc::new(
                new_globals
                    .iter()
                    .any(|p| p.requires_response_body_buffering()),
            ));
            self.global_requires_request_buffering.store(Arc::new(
                new_globals.iter().any(|p| p.modifies_request_body()),
            ));
            // Rebuild global protocol maps
            let mut new_global_proto = HashMap::with_capacity(protocols.len());
            for &proto in &protocols {
                new_global_proto.insert(proto, filter_for_protocol(&new_globals, proto));
            }
            self.global_protocol_plugins
                .store(Arc::new(new_global_proto));
        }

        Ok(())
    }

    /// Get the pre-resolved plugins for a proxy. Lock-free O(1) lookup.
    ///
    /// Returns an Arc to the cached plugin Vec — zero allocation per request.
    /// Callers iterate by reference; no Vec clone needed.
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
    #[allow(dead_code)] // Used by stream proxy handlers when protocol filtering is wired in
    pub fn get_plugins_for_protocol(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> Arc<Vec<Arc<dyn Plugin>>> {
        let map = self.protocol_plugins.load();
        // Use a temporary owned key for lookup — the hash map requires owned keys
        if let Some(plugins) = map.get(&(proxy_id.to_string(), protocol)) {
            Arc::clone(plugins)
        } else {
            // Fallback to global protocol-filtered plugins
            let globals = self.global_protocol_plugins.load();
            if let Some(plugins) = globals.get(&protocol) {
                Arc::clone(plugins)
            } else {
                // Should never happen, but return empty list
                Arc::new(Vec::new())
            }
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

    /// Check whether any plugin for this proxy modifies the request body.
    /// When true, the request body must be fully collected into memory before
    /// forwarding so plugins can transform it. When false, the body can be
    /// streamed directly to the backend without buffering.
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

    /// Number of proxy entries in the cache (for testing).
    #[allow(dead_code)]
    pub fn proxy_count(&self) -> usize {
        self.proxy_plugins.load().len()
    }

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
            }
        }

        // Step 2: For each proxy, resolve its full plugin list
        // (global + proxy-scoped, with proxy overriding global of same name)
        let mut proxy_map: HashMap<String, Arc<Vec<Arc<dyn Plugin>>>> =
            HashMap::with_capacity(config.proxies.len());
        let mut buffering_map: BufferingMap = HashMap::with_capacity(config.proxies.len());
        let mut req_buffering_map: RequestBufferingMap =
            HashMap::with_capacity(config.proxies.len());

        for proxy in &config.proxies {
            // Start with global plugins
            let mut merged = global_plugins.clone(); // Clones Arcs, not instances

            // Only look at plugin configs indexed for this proxy (O(plugins_per_proxy))
            if let Some(scoped_configs) = proxy_scoped_configs.get(proxy.id.as_str()) {
                let proxy_plugin_ids: std::collections::HashSet<&str> = proxy
                    .plugins
                    .iter()
                    .map(|a| a.plugin_config_id.as_str())
                    .collect();

                for pc in scoped_configs {
                    if proxy_plugin_ids.contains(pc.id.as_str()) {
                        match try_create_plugin(pc, http_client) {
                            Ok(Some(plugin)) => {
                                // Remove any global plugin of the same name
                                merged.retain(|p| p.name() != plugin.name());
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

            // Pre-compute whether any plugin modifies the request body
            let needs_req_buffering = merged.iter().any(|p| p.modifies_request_body());
            req_buffering_map.insert(proxy.id.clone(), needs_req_buffering);

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
        let global_needs_req_buffering = global_plugins.iter().any(|p| p.modifies_request_body());

        Ok((
            proxy_map,
            Arc::new(global_plugins),
            buffering_map,
            global_needs_buffering,
            req_buffering_map,
            global_needs_req_buffering,
        ))
    }
}
