//! Backend-neutral persistence policy shared by the SQL (`db_loader`) and
//! MongoDB (`mongo_store`) config stores.
//!
//! Each helper here is a pure function over domain types. It decides WHAT a
//! store must enforce (which identity values a consumer claims, which plugin
//! configs pin a consumer or an upstream, how an API-spec bundle is
//! canonicalized before hashing). HOW that is enforced — SQL `WHERE` clauses
//! and transactions versus Mongo filter documents and sessions — stays in
//! each backend. Keeping one copy means a policy fix cannot land on one
//! backend and silently miss the other.

use crate::admin::api_specs::{ExtractedBundle, hash_resource_bundle};
use crate::config::types::{Consumer, PluginConfig};
use crate::plugins::mesh_route_dispatch::MeshRouteDispatchConfig;
use std::collections::HashSet;

/// Deduped set of identity values a consumer claims within its namespace:
/// id, username, and custom_id (when present). Deduped because
/// self-collisions — a consumer whose own custom_id equals its own id or
/// username — are explicitly allowed (matching
/// `GatewayConfig::validate_unique_consumer_identities`); only cross-consumer
/// collisions must trip the `consumer_identity_index` primary key /
/// collection `_id`.
///
/// Returned sorted, so both stores write and release index entries in the
/// same order.
pub fn consumer_identity_values(consumer: &Consumer) -> Vec<&str> {
    consumer_identity_values_from_fields(
        &consumer.id,
        &consumer.username,
        consumer.custom_id.as_deref(),
    )
}

/// [`consumer_identity_values`] for a candidate that is not (yet) a
/// `Consumer`: the uniqueness prechecks probe the index with exactly the set
/// a write of these fields would claim. Which field a conflict message names
/// first stays with each backend's precheck.
pub fn consumer_identity_values_from_fields<'a>(
    id: &'a str,
    username: &'a str,
    custom_id: Option<&'a str>,
) -> Vec<&'a str> {
    let mut values = vec![id, username];
    if let Some(custom_id) = custom_id {
        values.push(custom_id);
    }
    values.sort_unstable();
    values.dedup();
    values
}

/// Whether an enabled `mesh_route_dispatch` plugin config routes to
/// `upstream_id`; an upstream delete must refuse while one does. Disabled
/// configs, other plugins, and configs that do not parse are not references.
pub fn mesh_route_dispatch_references_upstream_id(
    plugin: &PluginConfig,
    upstream_id: &str,
) -> bool {
    if !plugin.enabled || plugin.plugin_name != "mesh_route_dispatch" {
        return false;
    }
    MeshRouteDispatchConfig::from_value(&plugin.config)
        .is_ok_and(|config| config.references_upstream_id(upstream_id))
}

/// The first spec-owned upstream id (from `upstream_ids`) that an enabled
/// `mesh_route_dispatch` plugin config outside the spec routes to, in rule
/// order. Same enabled/plugin-name/parse filter as
/// [`mesh_route_dispatch_references_upstream_id`].
pub fn mesh_route_dispatch_referenced_upstream(
    plugin: &PluginConfig,
    upstream_ids: &HashSet<String>,
) -> Option<String> {
    if !plugin.enabled || plugin.plugin_name != "mesh_route_dispatch" {
        return None;
    }
    let config = MeshRouteDispatchConfig::from_value(&plugin.config).ok()?;
    config
        .rules
        .iter()
        .filter_map(|rule| rule.destination.upstream_id.as_deref())
        .find(|upstream_id| upstream_ids.contains(*upstream_id))
        .map(ToOwned::to_owned)
}

/// `access_control.allowed_consumers` names gateway Consumer usernames
/// (byte-for-byte). A delete must refuse while any plugin config in the
/// namespace still authorizes that username; the operator's policy is not
/// rewritten.
pub fn access_control_plugin_allows_consumer(config: &serde_json::Value, username: &str) -> bool {
    config
        .get("allowed_consumers")
        .and_then(|value| value.as_array())
        .is_some_and(|consumers| {
            consumers
                .iter()
                .any(|entry| entry.as_str() == Some(username))
        })
}

/// The `resource_hash` a store compares on API-spec replace: the bundle is
/// normalized exactly as admission normalizes stored rows (`normalize_fields`)
/// before `hash_resource_bundle`, so a resubmitted spec whose only difference
/// is, for example, host case hashes equal to the stored resources.
pub fn store_canonical_resource_hash(bundle: &ExtractedBundle) -> Result<String, anyhow::Error> {
    let mut proxy = bundle.proxy.clone();
    proxy.normalize_fields();
    let upstream = bundle.upstream.clone().map(|mut upstream| {
        upstream.normalize_fields();
        upstream
    });
    let mut plugins = bundle.plugins.clone();
    for plugin in &mut plugins {
        plugin.normalize_fields();
    }
    hash_resource_bundle(&ExtractedBundle {
        proxy,
        upstream,
        plugins,
    })
}
