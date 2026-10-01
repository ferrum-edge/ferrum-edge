//! `GET /proxies/{id}/mcp/tools`: read-only view of an `mcp_gateway` proxy's
//! cached tool catalog (issue #5926).
//!
//! The route is namespace-scoped like every other `/proxies` read, so the
//! dispatcher's namespace gate, `ns`-claim enforcement, and the viewer-key
//! namespace ceiling all apply before this handler runs.
//!
//! The catalog is node-local runtime state. This handler only reads what the
//! running `mcp_gateway` instances already cached: it never contacts an
//! upstream, never starts a refresh, and reports how old the catalog is. Every
//! role receives the same projection, and a server's `upstream_url` is always
//! reduced to its structural form (`scheme://host[:port]` plus markers), so no
//! userinfo, path token, query, or fragment is ever returned. Admins who need
//! the stored URL read the plugin config.

use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body_util::Full;
use hyper::{Response, StatusCode};
use serde_json::{Value, json};

use crate::admin::AdminState;
use crate::admin::crud::AdminResource;
use crate::admin::plugin_config_projection::redact_endpoint_url;
use crate::config::db_backend::namespaced_runtime_key;
use crate::config::types::{GatewayConfig, PluginConfig, PluginScope, Proxy, validate_resource_id};
use crate::plugins::mcp_gateway::{
    McpAdminCatalogSnapshot, McpAdminServerSnapshot, McpAdminToolSnapshot,
};

const MCP_GATEWAY_NOT_FOUND_MESSAGE: &str = "Proxy has no mcp_gateway plugin";

/// A proxy's effective `mcp_gateway` configs and where they were read from.
struct ResolvedGateways {
    configs: Vec<PluginConfig>,
    from_cache: bool,
    allowed_methods: Option<Vec<String>>,
}

pub(super) async fn handle_get_mcp_tool_catalog(
    state: &AdminState,
    proxy_id: &str,
    namespace: &str,
    pagination: &super::PaginationParams,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Err(message) = validate_resource_id(proxy_id) {
        return Ok(super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": message}),
        ));
    }
    let resolved = match resolve_gateways(state, namespace, proxy_id).await {
        Ok(Some(resolved)) => resolved,
        Ok(None) => {
            return Ok(super::json_response(
                StatusCode::NOT_FOUND,
                &json!({"error": Proxy::NOT_FOUND_MESSAGE}),
            ));
        }
        Err(response) => return Ok(*response),
    };
    if resolved.configs.is_empty() {
        return Ok(super::json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": MCP_GATEWAY_NOT_FOUND_MESSAGE}),
        ));
    }

    let mut snapshots = runtime_snapshots(
        state,
        namespace,
        proxy_id,
        resolved.allowed_methods.as_deref(),
    );
    let catalogs: Vec<(&PluginConfig, Option<McpAdminCatalogSnapshot>)> = resolved
        .configs
        .iter()
        .map(|config| {
            let path = configured_endpoint_path(config);
            let position = snapshots
                .iter()
                .position(|snapshot| Some(snapshot.endpoint_path.as_str()) == path);
            (config, position.map(|index| snapshots.swap_remove(index)))
        })
        .collect();

    let tools = catalogs.iter().flat_map(|(config, snapshot)| {
        snapshot
            .iter()
            .flat_map(|snapshot| snapshot.tools.iter())
            .map(move |tool| (config.id.as_str(), tool))
    });
    let mut body = super::paginate_mapped_response(tools, pagination, tool_entry_json);

    let refreshed_at = oldest_refresh(&catalogs);
    let stale = catalogs
        .iter()
        .any(|(_, snapshot)| catalog_state(snapshot.as_ref()) != "fresh");
    let catalogs_json: Vec<Value> = catalogs
        .iter()
        .map(|(config, snapshot)| catalog_json(config, snapshot.as_ref()))
        .collect();
    if let Some(object) = body.as_object_mut() {
        object.insert("proxy_id".to_string(), json!(proxy_id));
        object.insert("namespace".to_string(), json!(namespace));
        object.insert(
            "refreshed_at".to_string(),
            json!(refreshed_at.map(|at| at.to_rfc3339())),
        );
        object.insert("stale".to_string(), json!(stale));
        object.insert("catalogs".to_string(), Value::Array(catalogs_json));
    }
    if resolved.from_cache {
        Ok(super::json_response_with_stale(StatusCode::OK, &body))
    } else {
        Ok(super::json_response(StatusCode::OK, &body))
    }
}

/// The proxy's effective `mcp_gateway` configs, or `None` when the proxy does
/// not exist in `namespace`.
///
/// The proxy row is read exactly as `GET /proxies/{id}` reads it (store
/// first, cached configuration on a tolerated store failure). The effective
/// set follows the runtime merge: enabled proxy / proxy-group instances the
/// proxy associates, else enabled global instances in its namespace.
async fn resolve_gateways(
    state: &AdminState,
    namespace: &str,
    proxy_id: &str,
) -> Result<Option<ResolvedGateways>, Box<Response<Full<Bytes>>>> {
    let cached = state.cached_gateway_config();
    if let Some(db) = state.db.as_ref() {
        match db.get_proxy(namespace, proxy_id).await {
            Ok(None) => return Ok(None),
            Ok(Some(proxy)) => {
                let mut associated = Vec::with_capacity(proxy.plugins.len());
                for association in &proxy.plugins {
                    match db
                        .get_plugin_config(namespace, &association.plugin_config_id)
                        .await
                    {
                        Ok(Some(plugin)) => associated.push(plugin),
                        Ok(None) => {}
                        Err(error) => {
                            return Err(Box::new(PluginConfig::map_precheck_db_error(&error)));
                        }
                    }
                }
                let configs = effective_gateway_configs(&proxy, associated, cached.as_deref());
                return Ok(Some(ResolvedGateways {
                    configs,
                    from_cache: false,
                    allowed_methods: proxy.allowed_methods,
                }));
            }
            Err(error) => {
                if !Proxy::allow_cached_read_fallback(&error) {
                    return Err(Box::new(Proxy::map_precheck_db_error(&error)));
                }
                super::warn_persistence_failure_redacted("admin_mcp_tool_catalog_cached_fallback");
            }
        }
    }
    let Some(config) = cached else {
        return Err(Box::new(super::json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No database and no cached config available"}),
        )));
    };
    let Some(proxy) = config
        .proxies
        .iter()
        .find(|proxy| proxy.id == proxy_id && proxy.namespace == namespace)
    else {
        return Ok(None);
    };
    let associated = proxy
        .plugins
        .iter()
        .filter_map(|association| {
            cached_plugin_config(&config, namespace, &association.plugin_config_id)
        })
        .cloned()
        .collect();
    let configs = effective_gateway_configs(proxy, associated, Some(&*config));
    Ok(Some(ResolvedGateways {
        configs,
        from_cache: true,
        allowed_methods: proxy.allowed_methods.clone(),
    }))
}

fn cached_plugin_config<'a>(
    config: &'a GatewayConfig,
    namespace: &str,
    id: &str,
) -> Option<&'a PluginConfig> {
    config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.namespace == namespace && plugin.id == id)
}

/// The runtime merge for one proxy, restricted to `mcp_gateway`.
///
/// A store has no cheap "global plugins of a namespace" read, so the global
/// fallback comes from the cached configuration, which is also what the
/// running instances were built from.
fn effective_gateway_configs(
    proxy: &Proxy,
    associated: Vec<PluginConfig>,
    cached: Option<&GatewayConfig>,
) -> Vec<PluginConfig> {
    let local: Vec<PluginConfig> = associated
        .into_iter()
        .filter(|plugin| {
            plugin.enabled && plugin.plugin_name == "mcp_gateway" && scope_applies(plugin, proxy)
        })
        .collect();
    if !local.is_empty() {
        return local;
    }
    cached
        .map(|config| {
            config
                .plugin_configs
                .iter()
                .filter(|plugin| {
                    plugin.enabled
                        && plugin.scope == PluginScope::Global
                        && plugin.plugin_name == "mcp_gateway"
                        && plugin.namespace == proxy.namespace
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Whether an associated proxy / proxy-group instance applies to `proxy`.
/// Proxy-group instances omit `proxy_id`; the association makes them apply.
fn scope_applies(plugin: &PluginConfig, proxy: &Proxy) -> bool {
    match plugin.scope {
        PluginScope::Proxy => plugin.proxy_id.as_deref() == Some(proxy.id.as_str()),
        PluginScope::ProxyGroup => true,
        PluginScope::Global => false,
    }
}

fn configured_endpoint_path(config: &PluginConfig) -> Option<&str> {
    config
        .config
        .get("endpoint")
        .and_then(|endpoint| endpoint.get("path"))
        .and_then(Value::as_str)
}

/// Snapshots of the `mcp_gateway` instances this node runs for the proxy.
///
/// Empty when this process has no data plane (a control plane), or when its
/// data plane does not serve the proxy (another namespace, or a change that is
/// not live yet): a catalog exists only where the proxy is served.
fn runtime_snapshots(
    state: &AdminState,
    namespace: &str,
    proxy_id: &str,
    allowed_methods: Option<&[String]>,
) -> Vec<McpAdminCatalogSnapshot> {
    let Some(proxy_state) = state.proxy_state.as_ref() else {
        return Vec::new();
    };
    let served = proxy_state
        .config
        .load()
        .proxies
        .iter()
        .any(|proxy| proxy.id == proxy_id && proxy.namespace == namespace);
    if !served {
        return Vec::new();
    }
    let plugins = proxy_state
        .plugin_cache
        .load_inner()
        .get_plugins(&namespaced_runtime_key(namespace, proxy_id));
    plugins
        .iter()
        .filter_map(|plugin| plugin.mcp_gateway())
        .map(|gateway| gateway.admin_catalog_snapshot(allowed_methods))
        .collect()
}

/// The least recent refresh across the proxy's catalogs, `None` when any of
/// them has never been refreshed on this node.
fn oldest_refresh(
    catalogs: &[(&PluginConfig, Option<McpAdminCatalogSnapshot>)],
) -> Option<DateTime<Utc>> {
    let mut oldest: Option<DateTime<Utc>> = None;
    for (_, snapshot) in catalogs {
        let refreshed = snapshot.as_ref()?.refreshed_at?;
        if oldest.is_none_or(|current| refreshed < current) {
            oldest = Some(refreshed);
        }
    }
    oldest
}

/// `fresh`, `stale`, `not_refreshed`, `unmediated` (a `transparent_proxy`
/// instance has no catalog), or `not_served` (no running instance here).
fn catalog_state(snapshot: Option<&McpAdminCatalogSnapshot>) -> &'static str {
    match snapshot {
        None => "not_served",
        Some(snapshot) if snapshot.mode != "aggregate_router" => "unmediated",
        Some(snapshot) if snapshot.refreshed_at.is_none() => "not_refreshed",
        Some(snapshot) if snapshot.stale => "stale",
        Some(_) => "fresh",
    }
}

fn catalog_json(config: &PluginConfig, snapshot: Option<&McpAdminCatalogSnapshot>) -> Value {
    let state = catalog_state(snapshot);
    let Some(snapshot) = snapshot else {
        return json!({
            "plugin_config_id": config.id,
            "catalog_state": state,
            "refreshed_at": null,
            "stale": true,
            "tool_count": 0,
            "servers": [],
        });
    };
    json!({
        "plugin_config_id": config.id,
        "catalog_state": state,
        "mode": snapshot.mode,
        "enabled": snapshot.enabled,
        "endpoint_path": snapshot.endpoint_path,
        "refreshed_at": snapshot.refreshed_at.map(|at| at.to_rfc3339()),
        "stale": state != "fresh",
        "cache_ttl_seconds": snapshot.cache_ttl_seconds,
        "catalog_version": snapshot.catalog_version,
        "cached_sessions": snapshot.cached_sessions,
        "tool_count": snapshot.tools.len(),
        "tools_unavailable": snapshot.tools_unavailable,
        "discovery": {
            "on_new_tool": snapshot.on_new_tool,
            "on_schema_change": snapshot.on_schema_change,
        },
        "policy": {
            "default_action": snapshot.default_action,
            "hide_denied_tools": snapshot.hide_denied_tools,
        },
        "limits": {
            "max_catalog_items_per_list": snapshot.max_catalog_items_per_list,
            "max_catalog_bytes_per_list": snapshot.max_catalog_bytes_per_list,
        },
        "servers": snapshot.servers.iter().map(server_json).collect::<Vec<_>>(),
    })
}

fn server_json(server: &McpAdminServerSnapshot) -> Value {
    let refresh_error = match server.tools_refresh {
        "stale" => Some("the most recent tools/list refresh failed; last-good tools are served"),
        "failed" => Some("the most recent tools/list refresh failed and no last-good tools exist"),
        _ => None,
    };
    json!({
        "server_id": server.server_id,
        "namespace": server.namespace,
        "kind": server.kind,
        // Structural projection for every role: construction already refuses
        // userinfo, query, and fragment, and the path can carry a hosted MCP
        // server's ingest token.
        "upstream_url": server.upstream_url.as_deref().map(redact_endpoint_url),
        "enabled": server.enabled,
        "expose_tools": server.expose_tools,
        "tools_refresh": server.tools_refresh,
        "refresh_error": refresh_error,
    })
}

fn tool_entry_json((plugin_config_id, tool): (&str, &McpAdminToolSnapshot)) -> Value {
    let source = match &tool.operation {
        Some((method, path)) => json!({
            "type": "openapi",
            "server_id": tool.server_id,
            "namespace": tool.namespace,
            "operation_name": tool.upstream_name,
            "method": method,
            "path": path,
        }),
        None => json!({
            "type": "upstream",
            "server_id": tool.server_id,
            "namespace": tool.namespace,
            "upstream_name": tool.upstream_name,
        }),
    };
    json!({
        "name": tool.name,
        "plugin_config_id": plugin_config_id,
        "title": tool.title,
        "description": tool.description,
        "annotations": tool.annotations,
        "source": source,
        "policy": {
            "action": tool.action,
            "configured": tool.explicitly_configured,
            "effective": tool.effective,
            "listed": tool.listed,
            "callable": tool.callable,
        },
        "allowed_groups": tool.allowed_groups,
        "denied_groups": tool.denied_groups,
        "schema_hash": tool.schema_hash,
        "discovered_at": tool.discovered_at.to_rfc3339(),
    })
}
