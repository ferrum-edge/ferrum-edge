//! Opt-in authority for partial deployment mutations. Never used by runtime loading.

use crate::config::batch_atomicity::NamespaceConfigAdmissionLeaseRef;
use crate::config::db_backend::{
    ConditionalNamespaceSnapshot, MAX_NAMESPACE_SNAPSHOT_REPRESENTATION_BYTES, SnapshotDigest,
    SnapshotDigestWriter,
};
use crate::config::types::PluginScope;
use serde_json::Value;
use std::collections::HashSet;

/// Typed evidence and raw store evidence read from the same primary transaction.
/// Raw rows/documents retain unknown fields, credentials and association metadata;
/// binary values (stored spec documents included) are carried as a SHA-256
/// digest and length, never as the bytes themselves.
pub struct DeploymentSnapshot {
    pub snapshot: ConditionalNamespaceSnapshot,
    pub stored: Value,
}

impl DeploymentSnapshot {
    /// `{"profile": "deployment-v1", "resources": <namespace representation>,
    /// "stored": <raw evidence>}`. Materialize it only after [`Self::digest`]
    /// has accepted the snapshot within the representation bound.
    pub fn representation(&self) -> Result<Value, serde_json::Error> {
        Ok(serde_json::json!({
            "profile": "deployment-v1",
            "resources": self.snapshot.representation()?,
            "stored": self.stored,
        }))
    }

    /// Bounded digest of [`Self::representation`], streamed without
    /// materializing it.
    pub fn digest(&self) -> Result<SnapshotDigest, anyhow::Error> {
        self.digest_within(MAX_NAMESPACE_SNAPSHOT_REPRESENTATION_BYTES)
    }

    /// [`Self::digest`] with an explicit canonical-byte bound.
    pub fn digest_within(&self, limit: usize) -> Result<SnapshotDigest, anyhow::Error> {
        let mut writer = SnapshotDigestWriter::new(limit);
        let written = self.write_canonical(&mut writer);
        writer.finish(written)
    }

    fn write_canonical<W: std::io::Write>(&self, out: &mut W) -> std::io::Result<()> {
        // Keys in canonical (sorted) order: profile < resources < stored.
        out.write_all(br#"{"profile":"deployment-v1","resources":"#)?;
        self.snapshot.write_canonical(out)?;
        out.write_all(br#","stored":"#)?;
        crate::admin::preconditions::write_canonical_json_to(&self.stored, out)?;
        out.write_all(b"}")
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

/// Columns of each table rewritten by a conditional deployment replacement
/// that the typed resource model owns. A replacement writes these from the
/// submitted bundle and carries every other stored column forward unchanged,
/// so this list must equal the baseline schema's columns for each table: a
/// schema column missing here would silently keep its old value. The
/// `deployment_known_columns_match_the_baseline_schema` unit test fails on
/// any drift from `src/config/migrations/sql_dialect.rs`.
pub const DEPLOYMENT_KNOWN_COLUMNS: &[(&str, &[&str])] = &[
    (
        "proxies",
        &[
            "labels",
            "id",
            "namespace",
            "name",
            "hosts",
            "listen_path",
            "backend_scheme",
            "backend_host",
            "backend_port",
            "backend_path",
            "strip_listen_path",
            "preserve_host_header",
            "backend_connect_timeout_ms",
            "backend_read_timeout_ms",
            "backend_write_timeout_ms",
            "backend_tls_client_cert_path",
            "backend_tls_client_key_path",
            "backend_tls_verify_server_cert",
            "backend_tls_server_ca_cert_path",
            "dns_override",
            "dns_cache_ttl_seconds",
            "auth_mode",
            "upstream_id",
            "upstream_subset",
            "circuit_breaker",
            "retry",
            "response_body_mode",
            "pool_idle_timeout_seconds",
            "pool_enable_http_keep_alive",
            "pool_enable_http2",
            "pool_tcp_keepalive_seconds",
            "pool_http2_keep_alive_interval_seconds",
            "pool_http2_keep_alive_timeout_seconds",
            "pool_http2_initial_stream_window_size",
            "pool_http2_initial_connection_window_size",
            "pool_http2_adaptive_window",
            "pool_http2_max_frame_size",
            "pool_http2_max_concurrent_streams",
            "pool_http3_connections_per_backend",
            "pool_max_requests_per_connection",
            "listen_port",
            "frontend_tls",
            "passthrough",
            "udp_idle_timeout_seconds",
            "tcp_idle_timeout_seconds",
            "websocket_idle_timeout_seconds",
            "websocket_permessage_deflate",
            "allow_path_parameters",
            "allowed_methods",
            "allowed_ws_origins",
            "udp_max_response_amplification_factor",
            "stream_proxy_protocol",
            "backend_proxy_protocol",
            "stream_match",
            "api_spec_id",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "upstreams",
        &[
            "labels",
            "id",
            "namespace",
            "name",
            "targets",
            "algorithm",
            "hash_on",
            "hash_on_cookie_config",
            "health_checks",
            "service_discovery",
            "subsets",
            "backend_tls_client_cert_path",
            "backend_tls_client_key_path",
            "backend_tls_verify_server_cert",
            "backend_tls_server_ca_cert_path",
            "backend_tls_sni",
            "backend_tls_san_allow_list",
            "api_spec_id",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "plugin_configs",
        &[
            "labels",
            "id",
            "namespace",
            "plugin_name",
            "config",
            "scope",
            "proxy_id",
            "enabled",
            "priority_override",
            "trigger_json",
            "api_spec_id",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "proxy_plugins",
        &["namespace", "proxy_id", "plugin_config_id"],
    ),
];

/// The [`DEPLOYMENT_KNOWN_COLUMNS`] entry for `table`, if it is replaceable.
pub fn deployment_known_columns(table: &str) -> Option<&'static [&'static str]> {
    DEPLOYMENT_KNOWN_COLUMNS
        .iter()
        .find(|(name, _)| *name == table)
        .map(|(_, columns)| *columns)
}

/// Digest of the original expected representation, retained across
/// transaction retries.
pub struct DeploymentPrecondition<'a> {
    pub namespace: &'a str,
    pub expected: SnapshotDigest,
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
