use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::types::{GatewayConfig, PluginScope};
use crate::plugins::{Plugin, PluginHttpClient, create_plugin_with_http_client};

/// Pre-resolved plugin cache that avoids per-request plugin creation.
///
/// Plugins are created once at config load time and cached per proxy_id.
/// This is critical for stateful plugins like `rate_limiting` whose internal
/// DashMap state must persist across requests. Without caching, a new
/// rate limiter is created per request and limits are never enforced.
///
/// Rebuilt atomically via ArcSwap on config changes — reads are lock-free.
pub struct PluginCache {
    /// proxy_id → pre-resolved Vec<Arc<dyn Plugin>> (global + proxy-scoped, merged)
    proxy_plugins: ArcSwap<HashMap<String, Vec<Arc<dyn Plugin>>>>,
    /// Fallback: global plugins only (for proxies with no scoped overrides)
    global_plugins: ArcSwap<Vec<Arc<dyn Plugin>>>,
    /// Shared HTTP client for plugins that make outbound network calls.
    http_client: PluginHttpClient,
}

impl PluginCache {
    /// Build a new plugin cache from the given config.
    #[allow(dead_code)]
    pub fn new(config: &GatewayConfig) -> Self {
        let http_client = PluginHttpClient::default();
        let (proxy_map, globals) = Self::build_cache(config, &http_client);
        Self {
            proxy_plugins: ArcSwap::new(Arc::new(proxy_map)),
            global_plugins: ArcSwap::new(Arc::new(globals)),
            http_client,
        }
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

    /// Get the pre-resolved plugins for a proxy. Lock-free O(1) lookup.
    ///
    /// Returns Arc-cloned references to cached plugin instances —
    /// no new allocations, same instances across requests.
    pub fn get_plugins(&self, proxy_id: &str) -> Vec<Arc<dyn Plugin>> {
        let map = self.proxy_plugins.load();
        if let Some(plugins) = map.get(proxy_id) {
            plugins.clone() // Clones Arc pointers, not plugin instances
        } else {
            // Fallback to global-only plugins
            let globals = self.global_plugins.load();
            globals.as_ref().clone()
        }
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
    ) -> (HashMap<String, Vec<Arc<dyn Plugin>>>, Vec<Arc<dyn Plugin>>) {
        // Step 1: Create all enabled global plugins (shared across proxies)
        let mut global_plugins: Vec<Arc<dyn Plugin>> = Vec::new();
        for pc in &config.plugin_configs {
            if !pc.enabled {
                continue;
            }
            if pc.scope == PluginScope::Global
                && let Some(plugin) =
                    create_plugin_with_http_client(&pc.plugin_name, &pc.config, http_client.clone())
            {
                global_plugins.push(plugin);
            }
        }

        // Step 2: For each proxy, resolve its full plugin list
        // (global + proxy-scoped, with proxy overriding global of same name)
        let mut proxy_map: HashMap<String, Vec<Arc<dyn Plugin>>> = HashMap::new();

        for proxy in &config.proxies {
            let proxy_plugin_ids: Vec<&str> = proxy
                .plugins
                .iter()
                .map(|a| a.plugin_config_id.as_str())
                .collect();

            // Start with global plugins
            let mut merged = global_plugins.clone(); // Clones Arcs, not instances

            // Add proxy-scoped plugins, overriding globals of same name
            for pc in &config.plugin_configs {
                if !pc.enabled {
                    continue;
                }
                if pc.scope == PluginScope::Proxy
                    && pc.proxy_id.as_deref() == Some(&proxy.id)
                    && proxy_plugin_ids.contains(&pc.id.as_str())
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

            // Sort by priority so execution order is deterministic
            merged.sort_by_key(|p| p.priority());

            proxy_map.insert(proxy.id.clone(), merged);
        }

        // Sort global fallback list too
        global_plugins.sort_by_key(|p| p.priority());

        (proxy_map, global_plugins)
    }
}
