//! Declared configuration contract for a custom plugin (issue #6616).
//!
//! Plugin configs are closed documents: every JSON object a constructor reads,
//! at any depth, must reject keys it does not recognize. A typo in a nested
//! security-relevant key otherwise builds a plugin that silently enforces
//! something other than what the operator wrote. Configuration validation is
//! also by construction: admin, CP, and the runtime-less `ferrum-edge validate`
//! build the plugin and drop it, so constructors must stay pure (no tasks,
//! dials, file writes, or process-global registration; that work belongs in
//! [`super::Plugin::start_background_tasks`] /
//! [`super::Plugin::commit_background_tasks`]).
//!
//! Neither property is visible from outside the constructor, so every custom
//! plugin exports `config_contract()` returning this type. The plugin test
//! sweep (`tests/unit/plugins/plugin_config_closure_tests.rs`) runs the same
//! checks over custom plugins as over the built-ins: each example must
//! validate, validation must neither need a tokio runtime nor spawn a tokio
//! task, and an unknown key injected into the root or any nested object must
//! be rejected. The runtime check cannot observe blocking-pool work, OS
//! threads, dials, file writes, or global registration, so those stay a
//! constructor contract that review enforces.
//!
//! Path patterns are dotted JSON paths relative to the config root. `[]`
//! selects every array element and `*` matches any single object key, for
//! example `rules[].match` or `servers.*`.

use serde_json::Value;

/// Example configs and declared free-form regions for one plugin.
#[derive(Debug, Clone, Default)]
pub struct PluginConfigContract {
    /// Valid configs that together reach every nested object the plugin reads.
    pub examples: Vec<Value>,
    /// Objects whose keys are operator-chosen names (header maps, labels,
    /// named entries). The sweep does not inject a key into such an object,
    /// but still walks its values.
    pub free_form_objects: &'static [&'static str],
    /// Embedded foreign documents (a JSON Schema, an OpenAPI fragment, a
    /// sample payload) that the plugin does not interpret as its own schema.
    /// The sweep skips the whole subtree.
    pub opaque_documents: &'static [&'static str],
}

impl PluginConfigContract {
    /// A contract whose every nested object is closed.
    pub fn closed(examples: Vec<Value>) -> Self {
        Self {
            examples,
            free_form_objects: &[],
            opaque_documents: &[],
        }
    }

    /// Declare objects whose keys are operator-chosen names.
    pub fn with_free_form_objects(mut self, paths: &'static [&'static str]) -> Self {
        self.free_form_objects = paths;
        self
    }

    /// Declare embedded foreign documents the sweep must not walk.
    pub fn with_opaque_documents(mut self, paths: &'static [&'static str]) -> Self {
        self.opaque_documents = paths;
        self
    }
}
