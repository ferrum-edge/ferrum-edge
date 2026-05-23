use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::config::types::{Consumer, GatewayConfig, PluginConfig, Proxy, Upstream};

pub(crate) fn parse_backup_resources(query: Option<&str>) -> Option<HashSet<&str>> {
    let query = query?;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if let (Some(key), Some(val)) = (parts.next(), parts.next())
            && key == "resources"
        {
            return Some(
                val.split(',')
                    .map(str::trim)
                    .filter(|resource| !resource.is_empty())
                    .collect(),
            );
        }
    }
    None
}

pub(crate) fn parse_restore_confirm(query: Option<&str>) -> bool {
    let query = match query {
        Some(query) => query,
        None => return false,
    };
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if let (Some(key), Some(val)) = (parts.next(), parts.next())
            && key == "confirm"
            && val == "true"
        {
            return true;
        }
    }
    false
}

#[derive(Serialize)]
pub(crate) struct BackupPayload<'a> {
    pub(crate) version: &'a str,
    pub(crate) ferrum_version: &'static str,
    pub(crate) exported_at: String,
    pub(crate) source: &'static str,
    pub(crate) counts: BackupCounts,
    pub(crate) proxies: &'a [Proxy],
    pub(crate) consumers: &'a [Consumer],
    pub(crate) plugin_configs: &'a [PluginConfig],
    pub(crate) upstreams: &'a [Upstream],
}

#[derive(Serialize)]
pub(crate) struct BackupCounts {
    pub(crate) proxies: usize,
    pub(crate) consumers: usize,
    pub(crate) plugin_configs: usize,
    pub(crate) upstreams: usize,
}

#[derive(Deserialize)]
pub(crate) struct RestorePayload {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub proxies: Vec<Proxy>,
    #[serde(default)]
    pub consumers: Vec<Consumer>,
    #[serde(default)]
    pub plugin_configs: Vec<PluginConfig>,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
}

pub(crate) fn filter_config_by_namespace(config: &GatewayConfig, namespace: &str) -> GatewayConfig {
    GatewayConfig {
        version: config.version.clone(),
        proxies: config
            .proxies
            .iter()
            .filter(|proxy| proxy.namespace == namespace)
            .cloned()
            .collect(),
        consumers: config
            .consumers
            .iter()
            .filter(|consumer| consumer.namespace == namespace)
            .cloned()
            .collect(),
        plugin_configs: config
            .plugin_configs
            .iter()
            .filter(|plugin_config| plugin_config.namespace == namespace)
            .cloned()
            .collect(),
        upstreams: config
            .upstreams
            .iter()
            .filter(|upstream| upstream.namespace == namespace)
            .cloned()
            .collect(),
        ..config.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_config() -> GatewayConfig {
        serde_json::from_value(json!({
            "version": "1",
            "known_namespaces": ["tenant-a", "tenant-b"],
            "proxies": [
                {
                    "id": "proxy-a",
                    "namespace": "tenant-a",
                    "listen_path": "/a",
                    "backend_scheme": "http",
                    "backend_host": "a.internal",
                    "backend_port": 8080
                },
                {
                    "id": "proxy-b",
                    "namespace": "tenant-b",
                    "listen_path": "/b",
                    "backend_scheme": "http",
                    "backend_host": "b.internal",
                    "backend_port": 8080
                }
            ],
            "consumers": [
                {"id": "consumer-a", "username": "alice", "namespace": "tenant-a"},
                {"id": "consumer-b", "username": "bob", "namespace": "tenant-b"}
            ],
            "plugin_configs": [
                {
                    "id": "plugin-a",
                    "plugin_name": "key_auth",
                    "namespace": "tenant-a",
                    "scope": "global",
                    "config": {}
                },
                {
                    "id": "plugin-b",
                    "plugin_name": "key_auth",
                    "namespace": "tenant-b",
                    "scope": "global",
                    "config": {}
                }
            ],
            "upstreams": [
                {"id": "upstream-a", "name": "up-a", "namespace": "tenant-a", "targets": []},
                {"id": "upstream-b", "name": "up-b", "namespace": "tenant-b", "targets": []}
            ]
        }))
        .expect("sample config should deserialize")
    }

    #[test]
    fn parse_backup_resources_absent_query_is_unfiltered() {
        assert!(parse_backup_resources(None).is_none());
        assert!(parse_backup_resources(Some("page=1")).is_none());
    }

    #[test]
    fn parse_backup_resources_trims_and_ignores_empty_tokens() {
        let resources =
            parse_backup_resources(Some("download=true&resources=proxies, upstreams,,"))
                .expect("resources filter should parse");

        assert!(resources.contains("proxies"));
        assert!(resources.contains("upstreams"));
        assert_eq!(resources.len(), 2);
    }

    #[test]
    fn parse_restore_confirm_requires_true_value() {
        assert!(!parse_restore_confirm(None));
        assert!(!parse_restore_confirm(Some("confirm=false")));
        assert!(!parse_restore_confirm(Some("confirm=True")));
        assert!(parse_restore_confirm(Some("dry_run=false&confirm=true")));
    }

    #[test]
    fn filter_config_by_namespace_keeps_only_matching_resources() {
        let filtered = filter_config_by_namespace(&sample_config(), "tenant-a");

        assert_eq!(filtered.version, "1");
        assert_eq!(filtered.known_namespaces, vec!["tenant-a", "tenant-b"]);
        assert_eq!(filtered.proxies.len(), 1);
        assert_eq!(filtered.proxies[0].id, "proxy-a");
        assert_eq!(filtered.consumers.len(), 1);
        assert_eq!(filtered.consumers[0].id, "consumer-a");
        assert_eq!(filtered.plugin_configs.len(), 1);
        assert_eq!(filtered.plugin_configs[0].id, "plugin-a");
        assert_eq!(filtered.upstreams.len(), 1);
        assert_eq!(filtered.upstreams[0].id, "upstream-a");
    }

    #[test]
    fn filter_config_by_namespace_returns_empty_resource_sets_for_miss() {
        let filtered = filter_config_by_namespace(&sample_config(), "tenant-c");

        assert!(filtered.proxies.is_empty());
        assert!(filtered.consumers.is_empty());
        assert!(filtered.plugin_configs.is_empty());
        assert!(filtered.upstreams.is_empty());
        assert_eq!(filtered.known_namespaces, vec!["tenant-a", "tenant-b"]);
    }
}
