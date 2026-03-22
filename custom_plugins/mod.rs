//! Custom Plugins Registry
//!
//! This module is the extension point for third-party plugins. Add your custom
//! plugin modules here and register them in `create_custom_plugin()`.
//!
//! **You should never need to edit any files under `src/` to add custom plugins.**
//!
//! # Quick Start
//!
//! 1. Create your plugin file in this directory (e.g., `my_plugin.rs`)
//! 2. Declare it as a module below (e.g., `pub mod my_plugin;`)
//! 3. Register it in `create_custom_plugin()` by matching on your plugin name
//! 4. Add your plugin name to `custom_plugin_names()` for discovery
//! 5. Build with `cargo build --release`
//!
//! See `example_plugin.rs` for a complete working example, and
//! `CUSTOM_PLUGINS.md` at the project root for the full developer guide.

// ──────────────────────────────────────────────────────────────────────────────
// Step 1: Declare your custom plugin modules here.
//
// Example:
//   pub mod my_custom_auth;
//   pub mod my_custom_logger;
// ──────────────────────────────────────────────────────────────────────────────
pub mod example_plugin;

use serde_json::Value;
use std::sync::Arc;

use crate::plugins::{Plugin, PluginHttpClient};

// ──────────────────────────────────────────────────────────────────────────────
// Step 2: Register your custom plugins in this factory function.
//
// The gateway calls this function when a plugin name is not recognized as a
// built-in plugin. Return `Some(Arc<dyn Plugin>)` for your plugin names,
// or `None` to let the gateway log an "unknown plugin" warning.
// ──────────────────────────────────────────────────────────────────────────────

/// Create a custom plugin instance from its name and configuration.
///
/// This is called by the core plugin factory when a plugin name does not match
/// any built-in plugin. The `http_client` is the gateway's shared, pooled HTTP
/// client — use it for any outbound HTTP calls your plugin makes.
pub fn create_custom_plugin(
    name: &str,
    config: &Value,
    _http_client: PluginHttpClient,
) -> Option<Arc<dyn Plugin>> {
    match name {
        // ── Register your custom plugins here ────────────────────────────
        //
        // Example:
        //   "my_custom_auth" => Some(Arc::new(my_custom_auth::MyCustomAuth::new(config))),
        //   "my_custom_logger" => Some(Arc::new(my_custom_logger::MyCustomLogger::new(config, http_client))),
        //
        "example_plugin" => Some(Arc::new(example_plugin::ExamplePlugin::new(config))),
        _ => None,
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Step 3: List your custom plugin names for discovery via the admin API.
// ──────────────────────────────────────────────────────────────────────────────

/// Returns the names of all registered custom plugins.
///
/// Used by `available_plugins()` so the admin API and CLI can report the full
/// list of plugins supported by this build of the gateway.
pub fn custom_plugin_names() -> Vec<&'static str> {
    vec![
        // ── Add your plugin names here ───────────────────────────────────
        //
        // Example:
        //   "my_custom_auth",
        //   "my_custom_logger",
        //
        "example_plugin",
    ]
}
