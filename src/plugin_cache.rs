use arc_swap::ArcSwap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::config::types::{GatewayConfig, PluginScope};
use crate::plugins::{Plugin, PluginHttpClient, create_plugin_with_http_client};

/// A list of plugins shared across requests via Arc.
type PluginList = Arc<Vec<Arc<dyn Plugin>>>;
/// Map from proxy_id to its pre-resolved plugin list.
type ProxyPluginMap = HashMap<String, PluginList>;

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
    /// Shared HTTP client for plugins that make outbound network calls.
    http_client: PluginHttpClient,
}

impl PluginCache {
    /// Build a new plugin cache from the given config with a default HTTP client.
    pub fn new(config: &GatewayConfig) -> Self {
        let http_client = PluginHttpClient::default();
        Self::with_http_client(config, http_client)
    }

    /// Build a new plugin cache with a shared HTTP client configured from
    /// the gateway's pool settings. All plugins that make outbound HTTP calls
    /// (http_logging, future OTel exporters, etc.) share this client for
    /// connection reuse and keepalive.
    pub fn with_http_client(config: &GatewayConfig, http_client: PluginHttpClient) -> Self {
        let (proxy_map, globals) = Self::build_cache(config, &http_client);
        Self {
            proxy_plugins: ArcSwap::new(Arc::new(proxy_map)),
            global_plugins: ArcSwap::new(Arc::new(globals)),
            http_client,
        }
    }

    /// Atomically rebuild the cache when config changes.
    /// Old plugin instances (including rate limiter state) are dropped
    /// only after all in-flight requests using them complete.
    pub fn rebuild(&self, config: &GatewayConfig) {
        let (proxy_map, globals) = Self::build_cache(config, &self.http_client);
        self.proxy_plugins.store(Arc::new(proxy_map));
        self.global_plugins.store(Arc::new(globals));
    }

    /// Incrementally update the plugin cache, only rebuilding plugins for
    /// proxies identified in `proxy_ids_to_rebuild`. All other proxy plugin
    /// lists — including their stateful plugin instances (rate limiters, etc.)
    /// — are preserved unchanged.
    ///
    /// Also rebuilds global plugins if `rebuild_globals` is true (i.e., a
    /// global-scoped plugin config was added/modified/removed).
    pub fn apply_delta(
        &self,
        config: &GatewayConfig,
        proxy_ids_to_rebuild: &HashSet<String>,
        removed_proxy_ids: &[String],
        rebuild_globals: bool,
    ) {
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
                if pc.scope == PluginScope::Global
                    && let Some(plugin) = create_plugin_with_http_client(
                        &pc.plugin_name,
                        &pc.config,
                        self.http_client.clone(),
                    )
                {
                    global_plugins.push(plugin);
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
                    if proxy_plugin_ids.contains(pc.id.as_str())
                        && let Some(plugin) = create_plugin_with_http_client(
                            &pc.plugin_name,
                            &pc.config,
                            self.http_client.clone(),
                        )
                    {
                        merged.retain(|p| p.name() != plugin.name());
                        merged.push(plugin);
                    }
                }
            }

            merged.sort_by_key(|p| p.priority());
            new_map.insert(proxy.id.clone(), Arc::new(merged));
        }

        // Atomic swap — readers see old or new, never a partial state
        self.proxy_plugins.store(Arc::new(new_map));
        if rebuild_globals {
            self.global_plugins.store(Arc::new(new_globals));
        }
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
    ) -> (ProxyPluginMap, PluginList) {
        // Step 1: Create all enabled global plugins (shared across proxies)
        let mut global_plugins: Vec<Arc<dyn Plugin>> = Vec::new();

        // Pre-index proxy-scoped plugin configs by proxy_id for O(1) lookup
        // instead of scanning all plugin_configs for every proxy (O(P×C) → O(P+C)).
        let mut proxy_scoped_configs: HashMap<&str, Vec<&crate::config::types::PluginConfig>> =
            HashMap::new();

        for pc in &config.plugin_configs {
            if !pc.enabled {
                continue;
            }
            if pc.scope == PluginScope::Global {
                if let Some(plugin) =
                    create_plugin_with_http_client(&pc.plugin_name, &pc.config, http_client.clone())
                {
                    global_plugins.push(plugin);
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
                    if proxy_plugin_ids.contains(pc.id.as_str())
                        && let Some(plugin) = create_plugin_with_http_client(
                            &pc.plugin_name,
                            &pc.config,
                            http_client.clone(),
                        )
                    {
                        // Remove any global plugin of the same name
                        merged.retain(|p| p.name() != plugin.name());
                        merged.push(plugin);
                    }
                }
            }

            // Sort by priority so execution order is deterministic
            merged.sort_by_key(|p| p.priority());

            proxy_map.insert(proxy.id.clone(), Arc::new(merged));
        }

        // Sort global fallback list too
        global_plugins.sort_by_key(|p| p.priority());

        (proxy_map, Arc::new(global_plugins))
    }
}
