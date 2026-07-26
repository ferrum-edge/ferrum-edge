//! Shared incremental config application helpers.
//!
//! CP mode, ConfigSync, and xDS stream-local snapshots all consume the same
//! database delta shape. Keep the retain/upsert behavior centralized so those
//! paths cannot drift as resource types evolve.

use std::collections::{HashMap, HashSet};

use crate::config::db_loader::IncrementalResult;
use crate::config::types::GatewayConfig;

/// Apply an incremental result to a config snapshot in-place.
///
/// Removes deleted resources by `(namespace, id)`, upserts added/modified
/// resources by `(namespace, id)`, and updates `loaded_at` to the delta's poll
/// timestamp.
pub(crate) fn apply_incremental_to_config_snapshot(
    config: &mut GatewayConfig,
    result: IncrementalResult,
) {
    let poll_timestamp = result.poll_timestamp;
    apply_incremental_resources(config, result);
    config.loaded_at = poll_timestamp;
}

fn apply_incremental_resources(config: &mut GatewayConfig, result: IncrementalResult) {
    let removed_proxies: HashSet<(&str, &str)> = result
        .removed_proxy_ids
        .iter()
        .map(|key| (key.namespace.as_str(), key.id.as_str()))
        .collect();
    let removed_consumers: HashSet<(&str, &str)> = result
        .removed_consumer_ids
        .iter()
        .map(|key| (key.namespace.as_str(), key.id.as_str()))
        .collect();
    let removed_plugins: HashSet<(&str, &str)> = result
        .removed_plugin_config_ids
        .iter()
        .map(|key| (key.namespace.as_str(), key.id.as_str()))
        .collect();
    let removed_upstreams: HashSet<(&str, &str)> = result
        .removed_upstream_ids
        .iter()
        .map(|key| (key.namespace.as_str(), key.id.as_str()))
        .collect();

    config
        .proxies
        .retain(|proxy| !removed_proxies.contains(&(proxy.namespace.as_str(), proxy.id.as_str())));
    config.consumers.retain(|consumer| {
        !removed_consumers.contains(&(consumer.namespace.as_str(), consumer.id.as_str()))
    });
    config.plugin_configs.retain(|plugin| {
        !removed_plugins.contains(&(plugin.namespace.as_str(), plugin.id.as_str()))
    });
    config.upstreams.retain(|upstream| {
        !removed_upstreams.contains(&(upstream.namespace.as_str(), upstream.id.as_str()))
    });

    // Plugin associations are scoped by the owning proxy's namespace.
    for proxy in &mut config.proxies {
        proxy.plugins.retain(|assoc| {
            !removed_plugins.contains(&(proxy.namespace.as_str(), assoc.plugin_config_id.as_str()))
        });
    }

    // IDs are unique per namespace only — key every resource-type upsert by
    // `(namespace, id)` so a tenant update cannot overwrite a same-ID resource
    // belonging to another namespace.
    upsert_by_namespace_and_id(
        &mut config.proxies,
        result.added_or_modified_proxies,
        |proxy| proxy.namespace.as_str(),
        |proxy| proxy.id.as_str(),
    );
    upsert_by_namespace_and_id(
        &mut config.consumers,
        result.added_or_modified_consumers,
        |consumer| consumer.namespace.as_str(),
        |consumer| consumer.id.as_str(),
    );
    upsert_by_namespace_and_id(
        &mut config.plugin_configs,
        result.added_or_modified_plugin_configs,
        |plugin| plugin.namespace.as_str(),
        |plugin| plugin.id.as_str(),
    );
    upsert_by_namespace_and_id(
        &mut config.upstreams,
        result.added_or_modified_upstreams,
        |upstream| upstream.namespace.as_str(),
        |upstream| upstream.id.as_str(),
    );
}

fn upsert_by_namespace_and_id<T, FNs, FId>(
    existing: &mut Vec<T>,
    updates: Vec<T>,
    get_namespace: FNs,
    get_id: FId,
) where
    FNs: Fn(&T) -> &str,
    FId: Fn(&T) -> &str,
{
    let mut index: HashMap<(String, String), usize> = existing
        .iter()
        .enumerate()
        .map(|(i, item)| {
            (
                (get_namespace(item).to_string(), get_id(item).to_string()),
                i,
            )
        })
        .collect();

    for item in updates {
        let key = (get_namespace(&item).to_string(), get_id(&item).to_string());
        if let Some(&pos) = index.get(&key) {
            existing[pos] = item;
        } else {
            let pos = existing.len();
            existing.push(item);
            index.insert(key, pos);
        }
    }
}

/// Upsert items into a vec by ID: replace existing entries, append new ones.
///
/// Prefer [`upsert_by_namespace_and_id`] for GatewayConfig resources whose IDs
/// are only unique per namespace. This ID-only helper remains for generic
/// callers (e.g. control-plane unit tests) that intentionally key by a single
/// string.
#[cfg(test)]
pub(crate) fn upsert_by_id<T, F>(existing: &mut Vec<T>, updates: Vec<T>, get_id: F)
where
    F: Fn(&T) -> &str,
{
    let mut index: HashMap<String, usize> = existing
        .iter()
        .enumerate()
        .map(|(i, item)| (get_id(item).to_string(), i))
        .collect();

    for item in updates {
        let id = get_id(&item).to_string();
        if let Some(&pos) = index.get(id.as_str()) {
            existing[pos] = item;
        } else {
            let pos = existing.len();
            existing.push(item);
            index.insert(id, pos);
        }
    }
}
