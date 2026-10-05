//! Opt-in authority for partial deployment mutations. Never used by runtime loading.

use crate::config::batch_atomicity::NamespaceConfigAdmissionLeaseRef;
use crate::config::db_backend::ConditionalNamespaceSnapshot;
use crate::config::types::PluginScope;
use serde_json::Value;
use std::collections::HashSet;

/// Typed evidence and raw store evidence read from the same primary transaction.
/// Raw rows/documents retain unknown fields, credentials and association metadata.
pub struct DeploymentSnapshot {
    pub snapshot: ConditionalNamespaceSnapshot,
    pub stored: Value,
}

impl DeploymentSnapshot {
    pub fn representation(&self) -> Result<Value, serde_json::Error> {
        Ok(serde_json::json!({
            "profile": "deployment-v1",
            "resources": self.snapshot.representation()?,
            "stored": self.stored,
        }))
    }

    pub(crate) fn replacement_is_noop(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &crate::config::types::ApiSpec,
    ) -> Result<bool, anyhow::Error> {
        let config = &self.snapshot.config;
        let Some(previous_spec) = self.snapshot.api_specs.iter().find(|s| s.id == spec.id) else {
            return Ok(false);
        };
        let Some(mut proxy) = config
            .proxies
            .iter()
            .find(|p| p.id == spec.proxy_id)
            .cloned()
        else {
            return Ok(false);
        };
        let plugins: Vec<_> = config
            .plugin_configs
            .iter()
            .filter(|p| p.api_spec_id.as_deref() == Some(spec.id.as_str()))
            .cloned()
            .collect();
        let upstreams: Vec<_> = config
            .upstreams
            .iter()
            .filter(|u| u.api_spec_id.as_deref() == Some(spec.id.as_str()))
            .cloned()
            .collect();
        if upstreams.len() > 1 {
            return Ok(false);
        }
        let declared =
            crate::admin::api_specs::declared_proxy_plugin_association_ids_from_stored_spec(
                previous_spec,
            );
        let desired: HashSet<_> = bundle
            .proxy
            .plugins
            .iter()
            .map(|a| &a.plugin_config_id)
            .collect();
        let mut relevant: HashSet<_> = plugins.iter().map(|p| &p.id).collect();
        relevant.extend(declared.iter());
        relevant.extend(desired.iter().copied());
        let current: HashSet<_> = proxy
            .plugins
            .iter()
            .filter(|a| relevant.contains(&a.plugin_config_id))
            .map(|a| &a.plugin_config_id)
            .collect();
        if current != desired {
            return Ok(false);
        }
        proxy.plugins = bundle.proxy.plugins.clone();
        let current = crate::admin::api_specs::ExtractedBundle {
            proxy,
            upstream: upstreams.into_iter().next(),
            plugins,
        };
        Ok(!spec.resource_hash.is_empty()
            && crate::admin::api_specs::hash_resource_bundle(&current)?
                == crate::admin::api_specs::hash_resource_bundle(bundle)?)
    }

    /// Reject incomplete or inconsistent ownership before any selected mutation.
    pub fn removal_plan(&self, id: &str) -> Result<DeploymentRemovalPlan, anyhow::Error> {
        let config = &self.snapshot.config;
        if config.proxies.iter().filter(|p| p.id == id).count() != 1 {
            return Err(DeploymentGraphInvalid.into());
        }
        let proxy = config
            .proxies
            .iter()
            .find(|p| p.id == id)
            .ok_or(DeploymentGraphInvalid)?;
        let specs: Vec<_> = self
            .snapshot
            .api_specs
            .iter()
            .filter(|s| s.proxy_id == id)
            .collect();
        if specs.len() > 1 || specs.first().map(|s| s.id.as_str()) != proxy.api_spec_id.as_deref() {
            return Err(DeploymentGraphInvalid.into());
        }
        let spec_id = specs.first().map(|s| s.id.clone());
        if let Some(spec_id) = &spec_id
            && config
                .proxies
                .iter()
                .any(|p| p.id != id && p.api_spec_id.as_ref() == Some(spec_id))
        {
            return Err(DeploymentGraphInvalid.into());
        }
        if let Some(upstream_id) = &proxy.upstream_id {
            let upstream = config
                .upstreams
                .iter()
                .find(|u| &u.id == upstream_id)
                .ok_or(DeploymentGraphInvalid)?;
            if upstream.api_spec_id.is_some() && upstream.api_spec_id != spec_id {
                return Err(DeploymentGraphInvalid.into());
            }
        }
        let mut plugins = HashSet::new();
        for plugin in &config.plugin_configs {
            let owned = spec_id.is_some() && plugin.api_spec_id == spec_id;
            if owned || plugin.proxy_id.as_deref() == Some(id) {
                if plugin.scope != PluginScope::Proxy
                    || plugin.proxy_id.as_deref() != Some(id)
                    || (plugin.api_spec_id.is_some() && plugin.api_spec_id != spec_id)
                {
                    return Err(DeploymentGraphInvalid.into());
                }
                plugins.insert(plugin.id.clone());
            }
        }
        let mut associations = HashSet::new();
        for association in &proxy.plugins {
            if !associations.insert(&association.plugin_config_id) {
                return Err(DeploymentGraphInvalid.into());
            }
            let plugin = config
                .plugin_configs
                .iter()
                .find(|p| p.id == association.plugin_config_id)
                .ok_or(DeploymentGraphInvalid)?;
            match plugin.scope {
                PluginScope::Proxy if plugin.proxy_id.as_deref() == Some(id) => {}
                PluginScope::ProxyGroup
                    if plugin.proxy_id.is_none() && plugin.api_spec_id.is_none() =>
                {
                    if !config.proxies.iter().any(|p| {
                        p.id != id && p.plugins.iter().any(|a| a.plugin_config_id == plugin.id)
                    }) {
                        plugins.insert(plugin.id.clone());
                    }
                }
                _ => return Err(DeploymentGraphInvalid.into()),
            }
        }
        if config.proxies.iter().any(|p| {
            p.id != id
                && p.plugins
                    .iter()
                    .any(|a| plugins.contains(&a.plugin_config_id))
        }) {
            return Err(DeploymentGraphInvalid.into());
        }
        let upstreams = config
            .upstreams
            .iter()
            .filter(|u| spec_id.is_some() && u.api_spec_id == spec_id)
            .map(|u| u.id.clone())
            .collect();
        Ok(DeploymentRemovalPlan {
            spec_id,
            plugins,
            upstreams,
        })
    }
}

pub struct DeploymentRemovalPlan {
    pub spec_id: Option<String>,
    pub plugins: HashSet<String>,
    pub upstreams: HashSet<String>,
}

/// Original expected representation, retained across transaction retries.
pub struct DeploymentPrecondition<'a> {
    pub namespace: &'a str,
    pub expected: &'a Value,
    pub lease: NamespaceConfigAdmissionLeaseRef<'a>,
    pub validation_http_client: &'a crate::plugins::PluginHttpClient,
}

#[derive(Debug, Clone, Copy)]
pub struct DeploymentGraphInvalid;

impl std::fmt::Display for DeploymentGraphInvalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Deployment dependencies are missing or ownership is inconsistent")
    }
}

impl std::error::Error for DeploymentGraphInvalid {}

/// A proven external reference that refuses removal of a spec-owned upstream.
/// Driver, decoding and transaction failures must retain their own error types.
#[derive(Debug, Clone)]
pub(crate) enum ExternalSpecUpstreamConflict {
    Proxy {
        proxy_id: String,
        upstream_id: String,
        spec_id: String,
    },
    MeshRouteDispatch {
        plugin_config_id: String,
        upstream_id: String,
        spec_id: String,
    },
}

impl std::fmt::Display for ExternalSpecUpstreamConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proxy {
                proxy_id,
                upstream_id,
                spec_id,
            } => write!(
                f,
                "proxy {proxy_id:?} references a spec-owned upstream {upstream_id:?} \
                 from api_spec {spec_id:?}; detach it before replacing or deleting the API spec"
            ),
            Self::MeshRouteDispatch {
                plugin_config_id,
                upstream_id,
                spec_id,
            } => write!(
                f,
                "mesh_route_dispatch plugin_config {plugin_config_id:?} references a spec-owned \
                 upstream {upstream_id:?} from api_spec {spec_id:?}; \
                 detach it before replacing or deleting the API spec"
            ),
        }
    }
}

impl std::error::Error for ExternalSpecUpstreamConflict {}

/// Run the existing composition and named-schema admission rules against the
/// exact fenced candidate with the process-configured validation client.
pub(crate) async fn validate_deployment_candidate(
    candidate: &crate::config::types::GatewayConfig,
    http_client: &crate::plugins::PluginHttpClient,
) -> Result<(), anyhow::Error> {
    let candidate = candidate.clone();
    let http_client = http_client.clone();
    tokio::task::spawn_blocking(move || {
        crate::plugin_cache::validate_plugin_composition_candidate(&candidate, &http_client)
            .map_err(|_| DeploymentGraphInvalid)?;
        crate::plugin_cache::validate_tcp_connection_throttle_attachments(&candidate)
            .map_err(|_| DeploymentGraphInvalid)?;
        crate::plugins::transaction_log_schema::validate_config_graph(
            &candidate,
            &http_client,
            true,
        )
        .map_err(|_| DeploymentGraphInvalid)?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("Deployment validation task did not complete"))?
}

/// Store order is immaterial; field values and embedded array order are not.
pub(crate) fn sort_stored_rows(rows: &mut [Value]) {
    rows.sort_by_cached_key(|row| {
        let mut canonical = String::new();
        crate::admin::preconditions::write_canonical_json(row, &mut canonical);
        canonical
    });
}
