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
            return Some(val.split(',').collect());
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
