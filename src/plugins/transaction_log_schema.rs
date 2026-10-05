//! `transaction_log_schema` — config-only plugin that registers named
//! [`SummarySchema`] definitions for other logging plugins to reference
//! via `schema_ref:`.
//!
//! The plugin has no lifecycle hooks; it exists solely to carry compiled
//! schemas into the named-schemas registry. Loaders sort
//! `transaction_log_schema` plugins ahead of all others so the registry is
//! populated before any plugin tries to resolve a `schema_ref`.
//!
//! Restricted to `PluginScope::Global` — schemas are process-global.
//!
//! ## Config
//!
//! ```yaml
//! plugin_name: transaction_log_schema
//! scope: global
//! config:
//!   schemas:
//!     splunk_cim:
//!       summary_type: both
//!       rename: { proxy_id: route_id }
//!     datadog:
//!       summary_type: http
//!       static_fields: { source: "ferrum-edge" }
//! ```

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use tracing::warn;

use super::Plugin;
use crate::plugins::utils::log_schema::{
    SchemaCapabilities, SummarySchema, registry, resolve_schema,
};

/// Fixed-shape keys accepted by the outer plugin config. The `schemas` value
/// itself remains an intentionally open map keyed by operator-defined names.
pub const TRANSACTION_LOG_SCHEMA_CONFIG_KEYS: &[&str] = &["schemas"];

#[derive(Debug)]
pub struct TransactionLogSchema {
    /// Per-construction handle to every compiled schema. The registry retains
    /// its own `Arc`s after this config-only instance is discarded by cache
    /// construction.
    #[allow(dead_code)]
    schemas: HashMap<String, Arc<SummarySchema>>,
}

type CompiledSchemaEntry = (String, Arc<Value>, Arc<SummarySchema>);

impl TransactionLogSchema {
    /// Shape-only validation for admin/CP admission. Compiles every schema entry
    /// without staging anything in the process-global registry.
    pub(crate) fn validate_config(config: &Value) -> Result<(), String> {
        Self::validate_and_compile_entries(config)?;
        Ok(())
    }

    pub fn new(config: &Value) -> Result<Self, String> {
        let mut schemas: HashMap<String, Arc<SummarySchema>> = HashMap::new();
        for (name, raw, compiled) in Self::validate_and_compile_entries(config)? {
            schemas.insert(name.clone(), compiled.clone());
            // Register into the active staging area. Isolated constructor
            // validation is a no-op; graph validation and cache reloads open
            // explicit abort/commit brackets respectively.
            registry::register_named(&name, raw, compiled)?;
        }

        Ok(Self { schemas })
    }

    fn validate_and_compile_entries(config: &Value) -> Result<Vec<CompiledSchemaEntry>, String> {
        let config_object = config.as_object().ok_or_else(|| {
            "transaction_log_schema: config must be an object containing `schemas`".to_string()
        })?;
        for key in config_object.keys() {
            if !TRANSACTION_LOG_SCHEMA_CONFIG_KEYS.contains(&key.as_str()) {
                return Err(format!(
                    "transaction_log_schema: unknown config key {key:?} at `config` (valid keys: `{}`)",
                    TRANSACTION_LOG_SCHEMA_CONFIG_KEYS.join("`, `")
                ));
            }
        }
        let schemas_value = config_object.get("schemas").ok_or_else(|| {
            "transaction_log_schema: `schemas` is required (an object mapping name -> schema definition)".to_string()
        })?;
        let obj = schemas_value
            .as_object()
            .ok_or_else(|| "transaction_log_schema: `schemas` must be an object".to_string())?;
        if obj.is_empty() {
            return Err(
                "transaction_log_schema: `schemas` must contain at least one named schema"
                    .to_string(),
            );
        }

        let mut entries = Vec::with_capacity(obj.len());
        let mut seen_names = BTreeSet::new();
        for (name, schema_value) in obj {
            if name.is_empty() {
                return Err("transaction_log_schema: schema names must be non-empty".to_string());
            }
            if !seen_names.insert(name.clone()) {
                return Err(format!(
                    "transaction_log_schema: duplicate schema name {name:?} within the same plugin config"
                ));
            }
            // Compile (validates everything). Plugin name uses the schema
            // entry name so error messages point at the offending entry.
            // Named schemas are process-global and are registered under the
            // base capability set so ws-only field NAMES stay rejected in a
            // portable definition. The raw definition is retained so a
            // capability-bearing caller (`ws_logging`) can recompile it under
            // its own capability at `schema_ref` resolve time (see
            // `resolve_schema`), which is how disconnect fields reach parity
            // with an inline `ws_logging` schema.
            let plugin_label = format!("transaction_log_schema `schemas` entry {name:?}");
            let compiled =
                SummarySchema::compile(schema_value, &plugin_label, SchemaCapabilities::BASE)?;
            entries.push((name.clone(), Arc::new(schema_value.clone()), compiled));
        }

        Ok(entries)
    }

    /// All schemas declared by this plugin instance. Used by tests; future
    /// loader code can call this to publish schemas explicitly when the
    /// validation-mode `register_named` no-op is undesirable.
    #[allow(dead_code)]
    pub fn schemas(&self) -> &HashMap<String, Arc<SummarySchema>> {
        &self.schemas
    }
}

/// Whether a plugin config participates in the named log-schema graph.
///
/// Callers use this to avoid making unrelated plugin CRUD repair pre-existing
/// graph defects while still validating every mutation that can change schema
/// definitions or references.
pub(crate) fn participates_in_config_graph(
    plugin_config: &crate::config::types::PluginConfig,
) -> bool {
    plugin_config.plugin_name == "transaction_log_schema"
        || plugin_config.config.get("schema_ref").is_some()
}

/// Whether an enabled plugin config participates in the named-schema graph.
///
/// Disabled plugin configs are intentionally stageable without constructor,
/// policy, or graph validation until they are enabled.
pub(crate) fn is_enabled_config_graph_participant(
    plugin_config: &crate::config::types::PluginConfig,
) -> bool {
    plugin_config.enabled && participates_in_config_graph(plugin_config)
}

/// Validate enabled named schemas and all of their enabled referrers against
/// the supplied prospective configuration, without publishing anything to the
/// live registry.
///
/// Each namespace is staged independently because CP admin snapshots are
/// distributed to namespace-scoped DPs. Within a namespace, definitions are
/// always staged before referrers so declaration order is irrelevant. The
/// staging bracket is aborted after validation, preserving the live registry.
pub(crate) fn validate_config_graph(
    config: &crate::config::types::GatewayConfig,
    http_client: &crate::plugins::PluginHttpClient,
    optional_failures_are_errors: bool,
) -> Result<(), Vec<String>> {
    let namespaces: BTreeSet<&str> = config
        .plugin_configs
        .iter()
        .filter(|plugin| plugin.enabled && participates_in_config_graph(plugin))
        .map(|plugin| plugin.namespace.as_str())
        .collect();
    let mut errors = Vec::new();

    for namespace in namespaces {
        if let Err(error) = registry::begin_reload() {
            errors.push(format!(
                "transaction-log schema registry could not begin validation for namespace {namespace:?}: {error}"
            ));
            continue;
        }

        for plugin in config.plugin_configs.iter().filter(|plugin| {
            plugin.enabled
                && plugin.namespace == namespace
                && plugin.plugin_name == "transaction_log_schema"
        }) {
            if plugin.scope != crate::config::types::PluginScope::Global {
                errors.push(format!(
                    "Plugin {:?} (id={:?}, namespace={:?}): transaction_log_schema must have scope `global`",
                    plugin.plugin_name, plugin.id, namespace
                ));
                continue;
            }
            if let Err(error) = TransactionLogSchema::new(&plugin.config) {
                errors.push(format!(
                    "Plugin {:?} (id={:?}, namespace={:?}): {}",
                    plugin.plugin_name, plugin.id, namespace, error
                ));
            }
        }

        for plugin in config.plugin_configs.iter().filter(|plugin| {
            plugin.enabled
                && plugin.namespace == namespace
                && plugin.plugin_name != "transaction_log_schema"
                && plugin.config.get("schema_ref").is_some()
        }) {
            // Reference integrity is graph-fatal even for optional logging
            // plugins: fail-open applies to a malformed sink/filter, not to a
            // dangling or ambiguous prospective graph. BASE resolution checks
            // the shared invariants (type, mutual exclusion, existence); the
            // plugin constructor below performs any capability-specific
            // recompilation such as ws_logging's disconnect fields.
            if let Err(error) = resolve_schema(
                &plugin.config,
                &format!("plugin {:?}", plugin.plugin_name),
                SchemaCapabilities::BASE,
            ) {
                errors.push(format!(
                    "Plugin {:?} (id={:?}, namespace={:?}): {}",
                    plugin.plugin_name, plugin.id, namespace, error
                ));
                continue;
            }
            if let Err(error) = super::validate_plugin_config_with_http_client(
                &plugin.plugin_name,
                &plugin.config,
                http_client.clone(),
            ) {
                let message = format!(
                    "Plugin {:?} (id={:?}, namespace={:?}): {}",
                    plugin.plugin_name, plugin.id, namespace, error
                );
                if !optional_failures_are_errors
                    && super::plugin_failure_policy(&plugin.plugin_name)
                        == Some(super::PluginFailurePolicy::OptionalFailOpen)
                {
                    warn!(
                        "Optional plugin config validation warning: {}",
                        crate::startup::sanitize_startup_cause(message, &[])
                    );
                } else {
                    errors.push(message);
                }
            }
        }

        if let Err(error) = registry::abort_reload() {
            errors.push(format!(
                "transaction-log schema registry could not discard validation for namespace {namespace:?}: {error}"
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[async_trait]
impl Plugin for TransactionLogSchema {
    fn terminal_declaration(&self) -> crate::plugins::terminal_preparation::TerminalDeclaration {
        crate::plugins::terminal_preparation::TerminalDeclaration::PureNoop
    }

    fn name(&self) -> &str {
        "transaction_log_schema"
    }

    fn priority(&self) -> u16 {
        super::priority::TRANSACTION_LOG_SCHEMA
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::utils::log_schema::registry;
    use serde_json::json;

    // Tests that touch the registry hold the reload-bracket serializer
    // for their entire scope (reentrant with the internal begin/commit
    // calls inside the plugin construction).
    fn lock() -> registry::ReloadBracketTestGuard {
        registry::lock_for_tests()
    }

    #[test]
    fn missing_schemas_rejected() {
        let _g = lock();
        registry::reset_for_tests();
        let e = TransactionLogSchema::new(&json!({})).unwrap_err();
        assert!(e.contains("`schemas` is required"), "got: {e}");
    }

    #[test]
    fn empty_schemas_rejected() {
        let _g = lock();
        registry::reset_for_tests();
        let e = TransactionLogSchema::new(&json!({ "schemas": {} })).unwrap_err();
        assert!(e.contains("at least one"), "got: {e}");
    }

    #[test]
    fn schemas_not_object_rejected() {
        let _g = lock();
        registry::reset_for_tests();
        let e = TransactionLogSchema::new(&json!({ "schemas": [] })).unwrap_err();
        assert!(e.contains("must be an object"), "got: {e}");
    }

    #[test]
    fn empty_name_rejected() {
        let _g = lock();
        registry::reset_for_tests();
        let e = TransactionLogSchema::new(&json!({
            "schemas": { "": { "summary_type": "http" } }
        }))
        .unwrap_err();
        assert!(e.contains("non-empty"), "got: {e}");
    }

    #[test]
    fn bad_inner_schema_propagates_error() {
        let _g = lock();
        registry::reset_for_tests();
        let e = TransactionLogSchema::new(&json!({
            "schemas": {
                "good": { "summary_type": "http" },
                "bad":  { "omit": ["not_a_field"] }
            }
        }))
        .unwrap_err();
        // Compile errors are prefixed with the schema label.
        assert!(e.contains("entry \"bad\""), "got: {e}");
        assert!(
            e.contains("schema `omit` references unknown field \"not_a_field\""),
            "got: {e}"
        );
    }

    #[test]
    fn validation_call_does_not_pollute_registry() {
        let _g = lock();
        registry::reset_for_tests();
        // No begin_reload bracket — this simulates admin-API validation.
        let plugin = TransactionLogSchema::new(&json!({
            "schemas": {
                "splunk_cim": { "summary_type": "both", "rename": { "proxy_id": "route_id" } }
            }
        }))
        .expect("plugin constructed");
        assert_eq!(plugin.schemas().len(), 1);
        // Registry remains empty.
        assert!(registry::lookup_named("splunk_cim").is_none());
    }

    #[test]
    fn reload_bracket_publishes_to_registry() {
        let _g = lock();
        registry::reset_for_tests();
        registry::begin_reload().expect("reload bracket opens");
        let _plugin = TransactionLogSchema::new(&json!({
            "schemas": {
                "splunk_cim": { "summary_type": "both", "rename": { "proxy_id": "route_id" } },
                "datadog": { "summary_type": "http" }
            }
        }))
        .expect("plugin constructed");
        registry::commit_reload().expect("reload bracket commits");
        assert!(registry::lookup_named("splunk_cim").is_some());
        assert!(registry::lookup_named("datadog").is_some());
    }

    #[test]
    fn duplicate_across_plugins_in_reload_rejected() {
        let _g = lock();
        registry::reset_for_tests();
        registry::begin_reload().expect("reload bracket opens");
        let _p1 = TransactionLogSchema::new(&json!({
            "schemas": { "splunk_cim": { "summary_type": "both" } }
        }))
        .unwrap();
        let r = TransactionLogSchema::new(&json!({
            "schemas": { "splunk_cim": { "summary_type": "http" } }
        }));
        assert!(r.is_err());
        registry::abort_reload().expect("reload bracket aborts");
    }
}
