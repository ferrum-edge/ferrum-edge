//! Built-in plugin config contracts for the nested-closure and purity sweep in
//! `plugin_config_closure_tests.rs` (issue #6616).
//!
//! Each built-in's contract is its minimal config plus richer examples that
//! reach every nested object the plugin reads. A nested object missing from
//! the examples is simply not probed, so when a plugin gains a nested object,
//! add an example that populates it. Free-form and opaque declarations are
//! exemptions: each one needs a reason comment, and the sweep fails if one no
//! longer matches any example node.

use ferrum_edge::plugins::PluginConfigContract;

use super::plugin_utils::minimal_plugin_config;

mod ai_gateways;
mod ai_providers;
mod observability;
mod security;
mod traffic;

/// The sweep contract for a built-in plugin.
pub(crate) fn builtin_config_contract(name: &str) -> PluginConfigContract {
    let mut contract = ai_gateways::contract(name)
        .or_else(|| ai_providers::contract(name))
        .or_else(|| observability::contract(name))
        .or_else(|| security::contract(name))
        .or_else(|| traffic::contract(name))
        .unwrap_or_default();
    contract.examples.insert(0, minimal_plugin_config(name));
    contract
}
