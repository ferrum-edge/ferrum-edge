use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::types::{GatewayConfig, PluginScope};
use crate::plugins::{Plugin, create_plugin};

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
}

impl PluginCache {
    /// Build a new plugin cache from the given config.
    pub fn new(config: &GatewayConfig) -> Self {
        let (proxy_map, globals) = Self::build_cache(config);
        Self {
            proxy_plugins: ArcSwap::new(Arc::new(proxy_map)),
            global_plugins: ArcSwap::new(Arc::new(globals)),
        }
    }

    /// Atomically rebuild the cache when config changes.
    /// Old plugin instances (including rate limiter state) are dropped
    /// only after all in-flight requests using them complete.
    pub fn rebuild(&self, config: &GatewayConfig) {
        let (proxy_map, globals) = Self::build_cache(config);
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
    ) -> (HashMap<String, Vec<Arc<dyn Plugin>>>, Vec<Arc<dyn Plugin>>) {
        // Step 1: Create all enabled global plugins (shared across proxies)
        let mut global_plugins: Vec<Arc<dyn Plugin>> = Vec::new();
        for pc in &config.plugin_configs {
            if !pc.enabled {
                continue;
            }
            if pc.scope == PluginScope::Global
                && let Some(plugin) = create_plugin(&pc.plugin_name, &pc.config)
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
                    && let Some(plugin) = create_plugin(&pc.plugin_name, &pc.config)
                {
                    // Remove any global plugin of the same name
                    merged.retain(|p| p.name() != plugin.name());
                    merged.push(plugin);
                }
            }

            proxy_map.insert(proxy.id.clone(), merged);
        }

        (proxy_map, global_plugins)
    }
}
