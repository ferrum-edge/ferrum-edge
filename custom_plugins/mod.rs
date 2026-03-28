//! Custom Plugins — Auto-Discovered
//!
//! Drop a `.rs` file in this directory and rebuild — the build script
//! automatically discovers it, declares the module, and registers it in
//! the plugin factory.
//!
//! # Convention
//!
//! Each plugin file must export a factory function with this signature:
//!
//! ```ignore
//! pub fn create_plugin(
//!     config: &serde_json::Value,
//!     http_client: crate::plugins::PluginHttpClient,
//! ) -> Option<std::sync::Arc<dyn crate::plugins::Plugin>> {
//!     Some(std::sync::Arc::new(MyPlugin::new(config)))
//! }
//! ```
//!
//! The file name (without `.rs`) becomes the plugin name used in
//! gateway configuration. For example, `my_rate_limiter.rs` registers
//! as plugin name `"my_rate_limiter"`.
//!
//! # Filtering (optional)
//!
//! Set `FERRUM_CUSTOM_PLUGINS=plugin_a,plugin_b` at **build time** to
//! include only specific plugins. If unset, all `.rs` files in this
//! directory are included.
//!
//! See `CUSTOM_PLUGINS.md` for the full developer guide and
//! `example_plugin.rs` for a working example.

// Auto-generated module declarations (one `pub mod X;` per plugin file)
include!(concat!(env!("OUT_DIR"), "/custom_plugin_mods.rs"));

// Auto-generated factory function and name list
include!(concat!(env!("OUT_DIR"), "/custom_plugin_registry.rs"));
