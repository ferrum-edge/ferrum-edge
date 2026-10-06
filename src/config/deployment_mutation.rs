//! Opt-in authority for partial deployment mutations. Never used by runtime loading.

use crate::config::batch_atomicity::NamespaceConfigAdmissionLeaseRef;
use crate::config::db_backend::{
    ConditionalNamespaceSnapshot, MAX_NAMESPACE_SNAPSHOT_REPRESENTATION_BYTES, SnapshotByteBudget,
    SnapshotDigest, SnapshotDigestWriter,
};
use crate::config::types::PluginScope;
use serde_json::Value;
use std::collections::HashSet;

// Canonical framing of the deployment representation. Keys in canonical
// (sorted) order: profile < resources < stored.
const CANONICAL_HEAD: &[u8] = br#"{"profile":"deployment-v1","resources":"#;
const CANONICAL_STORED: &[u8] = br#","stored":"#;
const CANONICAL_TAIL: &[u8] = b"}";

/// Typed evidence and raw store evidence read from the same primary transaction.
/// Raw rows/documents retain unknown fields, credentials and association metadata;
/// binary values (stored spec documents included) are carried as a SHA-256
/// digest and length, never as the bytes themselves.
///
/// A snapshot assembled by [`StoredEvidence`] keeps the SHA-256 state of its
/// canonical head and typed snapshot, so [`Self::digest`] does not render the
/// typed snapshot again. Treat both fields as read-only once assembled.
pub struct DeploymentSnapshot {
    pub snapshot: ConditionalNamespaceSnapshot,
    pub stored: Value,
    typed_prefix: Option<CanonicalPrefix>,
}

/// SHA-256 state after the canonical head and typed snapshot, and how many
/// canonical bytes it absorbed.
struct CanonicalPrefix {
    hasher: crate::fips::approved::Sha256,
    len: usize,
}

impl CanonicalPrefix {
    fn absorb(&mut self, buf: &[u8]) {
        self.hasher.update(buf);
        self.len = self.len.saturating_add(buf.len());
    }
}

/// Charges each canonical byte against the evidence budget, then hashes it.
struct ChargedPrefix<'a> {
    budget: &'a mut SnapshotByteBudget,
    prefix: &'a mut CanonicalPrefix,
}

impl std::io::Write for ChargedPrefix<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Err(exceeded) = self.budget.charge(buf.len()) {
            return Err(std::io::Error::other(exceeded));
        }
        self.prefix.absorb(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl DeploymentSnapshot {
    /// A snapshot with no precomputed canonical prefix; [`Self::digest`]
    /// renders the whole representation.
    pub fn new(snapshot: ConditionalNamespaceSnapshot, stored: Value) -> Self {
        Self {
            snapshot,
            stored,
            typed_prefix: None,
        }
    }

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

    /// [`Self::representation`] by value: the raw evidence is moved, not
    /// deep-cloned, and the typed snapshot is handed back to the caller.
    pub fn into_representation(
        self,
    ) -> Result<(Value, ConditionalNamespaceSnapshot), serde_json::Error> {
        let resources = self.snapshot.representation()?;
        let mut representation = serde_json::Map::with_capacity(3);
        representation.insert("profile".to_string(), Value::from("deployment-v1"));
        representation.insert("resources".to_string(), resources);
        representation.insert("stored".to_string(), self.stored);
        Ok((Value::Object(representation), self.snapshot))
    }

    /// Bounded digest of [`Self::representation`], streamed without
    /// materializing it.
    pub fn digest(&self) -> Result<SnapshotDigest, anyhow::Error> {
        self.digest_within(MAX_NAMESPACE_SNAPSHOT_REPRESENTATION_BYTES)
    }

    /// [`Self::digest`] with an explicit canonical-byte bound.
    pub fn digest_within(&self, limit: usize) -> Result<SnapshotDigest, anyhow::Error> {
        // Resume after the typed snapshot hashed during evidence assembly
        // rather than rendering it a second time. The bound still covers it.
        if let Some(prefix) = &self.typed_prefix {
            let hasher = prefix.hasher.clone();
            let mut writer = SnapshotDigestWriter::resume(hasher, prefix.len, limit);
            let written = self.write_stored(&mut writer);
            return writer.finish(written);
        }
        let mut writer = SnapshotDigestWriter::new(limit);
        let written = self.write_canonical(&mut writer);
        writer.finish(written)
    }

    fn write_canonical<W: std::io::Write>(&self, out: &mut W) -> std::io::Result<()> {
        out.write_all(CANONICAL_HEAD)?;
        self.snapshot.write_canonical(out)?;
        self.write_stored(out)
    }

    /// The canonical bytes after the typed snapshot.
    fn write_stored<W: std::io::Write>(&self, out: &mut W) -> std::io::Result<()> {
        out.write_all(CANONICAL_STORED)?;
        crate::admin::preconditions::write_canonical_json_to(&self.stored, out)?;
        out.write_all(CANONICAL_TAIL)
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

/// The deployment mutation transaction's commit, or its acknowledgement,
/// failed: the store may have applied it. Every other deployment store error
/// is raised before commit is attempted and leaves nothing committed.
#[derive(Debug, Clone, Copy)]
pub struct DeploymentCommitOutcomeUnknown;

impl std::fmt::Display for DeploymentCommitOutcomeUnknown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Deployment mutation commit outcome is unknown")
    }
}

impl std::error::Error for DeploymentCommitOutcomeUnknown {}

/// Tag a failed deployment commit with [`DeploymentCommitOutcomeUnknown`],
/// retaining the driver error as its source.
pub fn deployment_commit_unknown<E>(error: E) -> anyhow::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    anyhow::Error::new(error)
        .context(DeploymentCommitOutcomeUnknown)
}

/// Whether `error` reports a deployment commit whose outcome is unknown.
pub fn is_deployment_commit_outcome_unknown(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<DeploymentCommitOutcomeUnknown>()
        .is_some()
}

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

/// Raw store evidence assembled under one canonical-byte budget shared with
/// the typed snapshot it accompanies. The typed snapshot and the framing are
/// charged first, so a namespace that is over the bound on its typed resources
/// alone is refused before any raw row or document is read. Every converted
/// row is then charged as it is produced, so an over-bound namespace is
/// refused before the rest of the raw evidence is materialized. The charges
/// sum to exactly the canonical length of the finished
/// [`DeploymentSnapshot`]'s representation, so this refuses precisely what
/// [`DeploymentSnapshot::digest_within`] would refuse at the same bound.
///
/// The pass that charges the typed snapshot also hashes it, so the snapshot
/// is rendered once per assembly; inside a mutation transaction that keeps a
/// second full rendering off the time namespace locks are held.
pub struct StoredEvidence {
    budget: SnapshotByteBudget,
    prefix: CanonicalPrefix,
    stored: serde_json::Map<String, Value>,
    rows: Vec<(String, Value)>,
}

impl StoredEvidence {
    /// Charge `snapshot` against [`MAX_NAMESPACE_SNAPSHOT_REPRESENTATION_BYTES`].
    pub fn for_snapshot(snapshot: &ConditionalNamespaceSnapshot) -> Result<Self, anyhow::Error> {
        Self::for_snapshot_within(snapshot, MAX_NAMESPACE_SNAPSHOT_REPRESENTATION_BYTES)
    }

    /// [`Self::for_snapshot`] with an explicit canonical-byte bound.
    pub fn for_snapshot_within(
        snapshot: &ConditionalNamespaceSnapshot,
        limit: usize,
    ) -> Result<Self, anyhow::Error> {
        let mut budget = SnapshotByteBudget::new(limit);
        // The framing, including the braces of the `stored` object.
        let framing = CANONICAL_HEAD.len() + CANONICAL_STORED.len() + CANONICAL_TAIL.len() + 2;
        budget.charge(framing)?;
        let mut prefix = CanonicalPrefix {
            hasher: crate::fips::approved::Sha256::new(),
            len: 0,
        };
        // The head is already charged as part of the framing.
        prefix.absorb(CANONICAL_HEAD);
        let written = snapshot.write_canonical(&mut ChargedPrefix {
            budget: &mut budget,
            prefix: &mut prefix,
        });
        budget.settle(written)?;
        Ok(Self {
            budget,
            prefix,
            stored: serde_json::Map::new(),
            rows: Vec::new(),
        })
    }

    /// Add one row or document of the table being collected, charging its
    /// canonical rendering (and separator) before it is retained.
    pub fn push(&mut self, row: Value) -> Result<(), anyhow::Error> {
        let mut canonical = String::new();
        crate::admin::preconditions::write_canonical_json(&row, &mut canonical);
        let separator = usize::from(!self.rows.is_empty());
        self.budget
            .charge(canonical.len().saturating_add(separator))?;
        self.rows.push((canonical, row));
        Ok(())
    }

    /// Close the table being collected under `name`. Store order is
    /// immaterial; field values and embedded array order are not, so rows are
    /// ordered by their canonical rendering.
    pub fn end_table(&mut self, name: &str) -> Result<(), anyhow::Error> {
        // `"name":[]` plus its separator. Table names are plain identifiers.
        let separator = usize::from(!self.stored.is_empty());
        self.budget
            .charge(name.len().saturating_add(5 + separator))?;
        let mut rows = std::mem::take(&mut self.rows);
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        let rows = rows.into_iter().map(|(_, row)| row).collect();
        self.stored.insert(name.to_string(), Value::Array(rows));
        Ok(())
    }

    /// `snapshot` must be the one passed to [`Self::for_snapshot`]: its
    /// canonical prefix was hashed there.
    pub fn finish(self, snapshot: ConditionalNamespaceSnapshot) -> DeploymentSnapshot {
        DeploymentSnapshot {
            snapshot,
            stored: Value::Object(self.stored),
            typed_prefix: Some(self.prefix),
        }
    }
}
