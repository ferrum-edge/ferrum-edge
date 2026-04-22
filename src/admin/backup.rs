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

/// Reject payloads that contain legacy proxy fields the scheme refactor
/// renamed. `#[serde(default)]` on `backend_scheme` means unknown keys
/// silently fall through — without this pre-check, a `/batch` or `/restore`
/// payload carrying `backend_protocol` would be accepted, leave proxies on
/// the default HTTPS scheme, and silently rewrite the config into a
/// different shape. The single-resource CRUD path performs the same check
/// in `Proxy::validate_raw_body`; this is the bulk-path equivalent.
pub(crate) fn check_legacy_proxy_fields(body: &[u8]) -> Result<(), String> {
    let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(body)
    else {
        return Ok(()); // Malformed JSON — deserialize below will surface it.
    };
    let Some(serde_json::Value::Array(proxies)) = map.get("proxies") else {
        return Ok(());
    };
    for (index, item) in proxies.iter().enumerate() {
        if let serde_json::Value::Object(proxy) = item
            && proxy.contains_key("backend_protocol")
        {
            let id_hint = proxy
                .get("id")
                .and_then(serde_json::Value::as_str)
                .map(|s| format!(" '{}'", s))
                .unwrap_or_else(|| format!(" at proxies[{}]", index));
            return Err(format!(
                "Proxy{}: field 'backend_protocol' was renamed to 'backend_scheme' (6-variant enum: \
                 http, https, tcp, tcps, udp, dtls). gRPC and WebSocket are now detected at \
                 runtime from the request; HTTP/3 is opt-in via 'backend_prefer_h3: true'.",
                id_hint
            ));
        }
    }
    Ok(())
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

    #[test]
    fn check_legacy_proxy_fields_accepts_modern_payload() {
        let body = br#"{
            "proxies": [
                {"id": "p1", "listen_path": "/v1", "backend_scheme": "https",
                 "backend_host": "localhost", "backend_port": 8443}
            ]
        }"#;
        assert!(check_legacy_proxy_fields(body).is_ok());
    }

    #[test]
    fn check_legacy_proxy_fields_rejects_backend_protocol() {
        // Bulk payload carrying the legacy field must be rejected BEFORE any
        // destructive restore / batch write — otherwise the payload parses
        // with backend_scheme defaulted to https, silently rewriting the
        // operator's config into a different shape than what they exported.
        let body = br#"{
            "proxies": [
                {"id": "legacy", "listen_path": "/v1", "backend_protocol": "grpc",
                 "backend_host": "localhost", "backend_port": 50051}
            ]
        }"#;
        let err = check_legacy_proxy_fields(body).expect_err("should reject");
        assert!(
            err.contains("backend_protocol"),
            "error should mention backend_protocol: {}",
            err
        );
        assert!(
            err.contains("backend_scheme"),
            "error should direct to new field: {}",
            err
        );
        assert!(
            err.contains("'legacy'"),
            "error should name the offending proxy id: {}",
            err
        );
    }

    #[test]
    fn check_legacy_proxy_fields_uses_index_when_id_absent() {
        let body = br#"{
            "proxies": [
                {"listen_path": "/v1", "backend_protocol": "http",
                 "backend_host": "localhost", "backend_port": 8080}
            ]
        }"#;
        let err = check_legacy_proxy_fields(body).expect_err("should reject");
        assert!(
            err.contains("proxies[0]"),
            "error should reference array index: {}",
            err
        );
    }

    #[test]
    fn check_legacy_proxy_fields_passes_through_on_malformed_json() {
        // Deserialize layer below is responsible for surfacing parse errors.
        // This helper intentionally stays silent on junk input so the
        // existing error path isn't duplicated.
        assert!(check_legacy_proxy_fields(b"not json").is_ok());
    }

    #[test]
    fn check_legacy_proxy_fields_ignores_empty_proxies_array() {
        let body = br#"{"proxies": []}"#;
        assert!(check_legacy_proxy_fields(body).is_ok());
    }
}
