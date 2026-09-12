//! Informational application attribution for provisioning clients.

use std::collections::BTreeMap;

use crate::config::types::{Consumer, PluginConfig, Proxy, Upstream};
use hyper::HeaderMap;

pub const PROVISIONED_BY_LABEL: &str = "provisioned-by";
pub const PROVISIONED_BY_HEADER: &str = "x-ferrum-provisioned-by";

/// This is caller-supplied metadata, never authorization or deletion authority.
/// The stored value is trimmed so one client name never becomes several
/// label values that differ only in surrounding whitespace.
pub fn provisioner(headers: &HeaderMap) -> Result<Option<String>, String> {
    let mut values = headers.get_all(PROVISIONED_BY_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err("X-Ferrum-Provisioned-By must occur only once".to_string());
    }
    let value = value
        .to_str()
        .map_err(|_| "X-Ferrum-Provisioned-By must be text")?;
    if value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err("X-Ferrum-Provisioned-By must be nonblank, at most 512 bytes, and contain no control characters".to_string());
    }
    Ok(Some(value.trim().to_string()))
}

/// Keep an imported resource's recorded origin and every operator label.
pub fn stamp(labels: &mut BTreeMap<String, String>, provisioner: Option<&str>) {
    if let Some(value) = provisioner {
        labels
            .entry(PROVISIONED_BY_LABEL.to_string())
            .or_insert_with(|| value.to_string());
    }
}

/// Label typed bulk resources after strict decoding, without copying or
/// re-encoding the upload. Restore's spec-owned graph must keep its hash.
pub fn stamp_resources(
    proxies: &mut [Proxy],
    consumers: &mut [Consumer],
    upstreams: &mut [Upstream],
    plugins: &mut [PluginConfig],
    provisioner: Option<&str>,
    restore: bool,
) {
    for proxy in proxies {
        if !restore || proxy.api_spec_id.is_none() {
            stamp(&mut proxy.labels, provisioner);
        }
    }
    for consumer in consumers {
        stamp(&mut consumer.labels, provisioner);
    }
    for upstream in upstreams {
        if !restore || upstream.api_spec_id.is_none() {
            stamp(&mut upstream.labels, provisioner);
        }
    }
    for plugin in plugins {
        if !restore || plugin.api_spec_id.is_none() {
            stamp(&mut plugin.labels, provisioner);
        }
    }
}
