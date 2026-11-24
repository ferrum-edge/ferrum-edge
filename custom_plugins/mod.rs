//! Custom Plugins — Auto-Discovered
//!
//! Drop a `.rs` file in this directory and rebuild — the build script
//! automatically discovers it, declares the module, and registers it in
//! the plugin factory.
//!
//! Pedagogical examples live under `custom_plugins/examples/` and are **not**
//! compiled unless listed in `FERRUM_CUSTOM_PLUGINS` (see
//! `custom_plugins/examples/README.md`).
//!
//! # Convention
//!
//! Each plugin file must export a factory function with this signature:
//!
//! ```ignore
//! pub fn create_plugin(
//!     config: &serde_json::Value,
//!     http_client: crate::plugins::PluginHttpClient,
//! ) -> Result<Option<std::sync::Arc<dyn crate::plugins::Plugin>>, String> {
//!     Ok(Some(std::sync::Arc::new(MyPlugin::new(config)?)))
//! }
//!
//! pub fn failure_policy() -> crate::plugins::PluginFailurePolicy {
//!     crate::plugins::PluginFailurePolicy::KeepLastKnownGood
//! }
//!
//! pub fn config_contract() -> crate::plugins::PluginConfigContract {
//!     crate::plugins::PluginConfigContract::closed(vec![serde_json::json!({})])
//! }
//! ```
//!
//! The `new()` constructor must return `Result<Self, String>` and validate the
//! plugin config — return `Err` for missing required fields, invalid values,
//! unknown keys at any depth, or configs that would make the plugin a no-op.
//! It must also be free of side effects (no tasks, dials, file writes, or
//! process-global registration): config validation constructs and drops it.
//!
//! `config_contract()` lists example configs (plus any free-form maps or
//! embedded foreign documents). The plugin test sweep validates each example,
//! checks that construction neither needs nor spawns onto a tokio runtime, and
//! injects an unknown key into every nested object to prove it is rejected.
//!
//! The file name (without `.rs`) becomes the plugin name used in
//! gateway configuration. For example, `my_rate_limiter.rs` registers
//! as plugin name `"my_rate_limiter"`.
//!
//! # Filtering (optional)
//!
//! Set `FERRUM_CUSTOM_PLUGINS=plugin_a,plugin_b` at **build time** to
//! include only specific plugins. If unset, all `.rs` files directly in this
//! directory are included. Example plugins under `examples/` require an
//! explicit listing (for example
//! `FERRUM_CUSTOM_PLUGINS=example_audit_plugin`).
//!
//! See `CUSTOM_PLUGINS.md` for the full developer guide and
//! `examples/example_plugin.rs` for a working example.

// Auto-generated module declarations (one `pub mod X;` per plugin file)
include!(concat!(env!("OUT_DIR"), "/custom_plugin_mods.rs"));

// Auto-generated factory function and name list
include!(concat!(env!("OUT_DIR"), "/custom_plugin_registry.rs"));
