//! Database backend trait — abstracts config storage for SQL (sqlx) and NoSQL (MongoDB) backends.
//!
//! All database operations needed by the admin API, operating modes, and config
//! polling are defined here. Each backend (sqlx, MongoDB) provides its own
//! implementation. The trait is object-safe so it can be used as `Arc<dyn DatabaseBackend>`.

use crate::config::types::{
    ApiSpec, Consumer, GatewayConfig, PluginConfig, PluginScope, Proxy, Upstream,
};
use crate::plugins::PluginHttpClient;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use percent_encoding::percent_decode_str;
use std::collections::HashSet;

/// Validate that a plugin row can be restored as an explicit association on
/// `proxy_id`. Global plugins are inherited rather than associated, while a
/// proxy-scoped plugin may only be attached to its own target proxy.
pub(crate) fn validate_api_spec_proxy_plugin_association(
    plugin: &PluginConfig,
    proxy_id: &str,
) -> Result<(), anyhow::Error> {
    match plugin.scope {
        PluginScope::Global => anyhow::bail!(
            "API-spec restore associated plugin '{}' is global and cannot be associated explicitly with proxy '{}'",
            plugin.id,
            proxy_id
        ),
        PluginScope::Proxy if plugin.proxy_id.as_deref() != Some(proxy_id) => anyhow::bail!(
            "API-spec restore associated plugin '{}' targets proxy '{}', not restored proxy '{}'",
            plugin.id,
            plugin.proxy_id.as_deref().unwrap_or("<none>"),
            proxy_id
        ),
        PluginScope::ProxyGroup if plugin.proxy_id.is_some() => anyhow::bail!(
            "API-spec restore associated proxy-group plugin '{}' unexpectedly carries proxy_id '{}'",
            plugin.id,
            plugin.proxy_id.as_deref().unwrap_or("<none>")
        ),
        PluginScope::Proxy | PluginScope::ProxyGroup => Ok(()),
    }
}

/// Project a namespace transaction candidate down to the recovered proxy graph.
///
/// Restore must fail closed for the proxy it is publishing, including attached
/// shared proxy-group rows, effective global rows, and unattached proxy-scoped
/// rows that the cascade removed. Unrelated malformed associations remain
/// available for in-band repair and must not make otherwise-valid compensation
/// impossible.
pub(crate) fn api_spec_recovered_proxy_graph(
    mut candidate: GatewayConfig,
    proxy_id: &str,
) -> Result<GatewayConfig, anyhow::Error> {
    let restored_proxy = candidate
        .proxies
        .iter()
        .find(|proxy| proxy.id == proxy_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("API-spec restore proxy '{}' is missing", proxy_id))?;
    let associated_plugin_ids: HashSet<&str> = restored_proxy
        .plugins
        .iter()
        .map(|association| association.plugin_config_id.as_str())
        .collect();
    candidate.plugin_configs.retain(|plugin| {
        plugin.scope == PluginScope::Global
            || associated_plugin_ids.contains(plugin.id.as_str())
            || plugin.proxy_id.as_deref() == Some(proxy_id)
    });
    candidate.proxies.clear();
    candidate.proxies.push(restored_proxy);
    Ok(candidate)
}

/// Re-run the plugin composition and named-schema contracts against the exact
/// recovered proxy graph. Compensation can follow an intervening writer, so
/// the pre-delete admission result is no longer authoritative when the restore
/// transaction commits.
pub(crate) async fn validate_api_spec_recovered_plugin_graph(
    candidate: &GatewayConfig,
    http_client: &PluginHttpClient,
) -> Result<(), anyhow::Error> {
    let candidate = candidate.clone();
    let http_client = http_client.clone();
    tokio::task::spawn_blocking(move || {
        for plugin in &candidate.plugin_configs {
            crate::plugins::validate_plugin_config_with_http_client(
                &plugin.plugin_name,
                &plugin.config,
                http_client.clone(),
            )
            .map_err(|error| {
                anyhow::anyhow!(
                    "API-spec restore plugin '{}' validation failed: {}",
                    plugin.id,
                    error
                )
            })?;
        }
        crate::plugin_cache::validate_plugin_composition_candidate(&candidate, &http_client)
            .map_err(anyhow::Error::msg)?;
        crate::plugins::transaction_log_schema::validate_config_graph(
            &candidate,
            &http_client,
            true,
        )
        .map_err(|errors| {
            anyhow::anyhow!(
                "API-spec restore produced an invalid transaction-log schema graph: {}",
                errors.join("; ")
            )
        })
    })
    .await
    .map_err(|error| anyhow::anyhow!("API-spec restore graph validation task failed: {error}"))?
}

/// Validate the immutable identity and ownership boundaries of an API-spec
/// bundle before a backend starts an atomic restore.
///
/// A restore deliberately avoids upserts. These checks make that contract
/// explicit: normal submissions must be unstamped, compensation resources must
/// be stamped with this spec, and compensating upstreams and plugins preserve
/// their exact ownership. Backends may reuse an additional hand-owned upstream
/// only after validating its stable pre-delete identity.
pub(crate) fn validate_api_spec_restore_inputs(
    bundle: &crate::admin::api_specs::ExtractedBundle,
    spec: &ApiSpec,
    additional_upstreams: &[Upstream],
    additional_plugins: &[PluginConfig],
    compensation_restore: bool,
) -> Result<(), anyhow::Error> {
    if bundle.proxy.id != spec.proxy_id {
        anyhow::bail!(
            "API-spec restore proxy id '{}' does not match spec proxy_id '{}'",
            bundle.proxy.id,
            spec.proxy_id
        );
    }
    if bundle.proxy.namespace != spec.namespace {
        anyhow::bail!(
            "API-spec restore proxy namespace '{}' does not match spec namespace '{}'",
            bundle.proxy.namespace,
            spec.namespace
        );
    }
    match (bundle.proxy.api_spec_id.as_deref(), compensation_restore) {
        (Some(owner), true) if owner != spec.id => anyhow::bail!(
            "API-spec restore proxy '{}' is owned by a different API spec",
            bundle.proxy.id
        ),
        (None, true) => anyhow::bail!(
            "API-spec restore proxy '{}' is not owned by API spec '{}'",
            bundle.proxy.id,
            spec.id
        ),
        (Some(_), false) => anyhow::bail!(
            "API-spec submission proxy '{}' carries server-managed API-spec ownership",
            bundle.proxy.id
        ),
        (Some(_), true) | (None, false) => {}
    }

    if let Some(upstream) = &bundle.upstream {
        if upstream.namespace != spec.namespace {
            anyhow::bail!(
                "API-spec restore upstream '{}' belongs to namespace '{}', not '{}'",
                upstream.id,
                upstream.namespace,
                spec.namespace
            );
        }
        match (upstream.api_spec_id.as_deref(), compensation_restore) {
            (Some(owner), true) if owner != spec.id => anyhow::bail!(
                "API-spec restore upstream '{}' is owned by a different API spec",
                upstream.id
            ),
            (None, true) => anyhow::bail!(
                "API-spec restore upstream '{}' is not owned by API spec '{}'",
                upstream.id,
                spec.id
            ),
            (Some(_), false) => anyhow::bail!(
                "API-spec submission upstream '{}' carries server-managed API-spec ownership",
                upstream.id
            ),
            (Some(_), true) | (None, false) => {}
        }
    }

    let mut inserted_upstream_ids = HashSet::with_capacity(
        bundle
            .upstream
            .iter()
            .count()
            .saturating_add(additional_upstreams.len()),
    );
    if let Some(upstream) = &bundle.upstream {
        inserted_upstream_ids.insert(upstream.id.as_str());
    }
    for upstream in additional_upstreams {
        if upstream.namespace != spec.namespace {
            anyhow::bail!(
                "API-spec restore additional upstream '{}' belongs to namespace '{}', not '{}'",
                upstream.id,
                upstream.namespace,
                spec.namespace
            );
        }
        if upstream
            .api_spec_id
            .as_deref()
            .is_some_and(|owner| owner != spec.id.as_str())
        {
            anyhow::bail!(
                "API-spec restore additional upstream '{}' is owned by a different API spec",
                upstream.id
            );
        }
        if !inserted_upstream_ids.insert(upstream.id.as_str()) {
            anyhow::bail!(
                "API-spec restore contains overlapping upstream id '{}'",
                upstream.id
            );
        }
    }

    let mut association_ids = HashSet::with_capacity(bundle.proxy.plugins.len());
    for association in &bundle.proxy.plugins {
        if !association_ids.insert(association.plugin_config_id.as_str()) {
            anyhow::bail!(
                "API-spec restore proxy '{}' contains duplicate association to plugin '{}'",
                bundle.proxy.id,
                association.plugin_config_id
            );
        }
    }

    let mut inserted_plugin_ids = HashSet::with_capacity(
        bundle
            .plugins
            .len()
            .saturating_add(additional_plugins.len()),
    );
    for plugin in &bundle.plugins {
        if plugin.namespace != spec.namespace {
            anyhow::bail!(
                "API-spec restore plugin '{}' belongs to namespace '{}', not '{}'",
                plugin.id,
                plugin.namespace,
                spec.namespace
            );
        }
        match (plugin.api_spec_id.as_deref(), compensation_restore) {
            (Some(owner), true) if owner != spec.id => anyhow::bail!(
                "API-spec restore plugin '{}' is owned by a different API spec",
                plugin.id
            ),
            (None, true) => anyhow::bail!(
                "API-spec restore plugin '{}' is not owned by API spec '{}'",
                plugin.id,
                spec.id
            ),
            (Some(_), false) => anyhow::bail!(
                "API-spec submission plugin '{}' carries server-managed API-spec ownership",
                plugin.id
            ),
            (Some(_), true) | (None, false) => {}
        }
        if compensation_restore && plugin.scope == PluginScope::Global && plugin.proxy_id.is_some()
        {
            anyhow::bail!(
                "API-spec restore global plugin '{}' unexpectedly carries proxy_id '{}'",
                plugin.id,
                plugin.proxy_id.as_deref().unwrap_or("<none>")
            );
        }
        let is_proxy_scoped_to_bundle = plugin.scope == PluginScope::Proxy
            && plugin.proxy_id.as_deref() == Some(bundle.proxy.id.as_str());
        let is_unassociated_compensation_global = compensation_restore
            && plugin.scope == PluginScope::Global
            && plugin.proxy_id.is_none()
            && !association_ids.contains(plugin.id.as_str());
        if !is_proxy_scoped_to_bundle && !is_unassociated_compensation_global {
            anyhow::bail!(
                "API-spec restore plugin '{}' is not proxy-scoped to proxy '{}'",
                plugin.id,
                bundle.proxy.id
            );
        }
        if !inserted_plugin_ids.insert(plugin.id.as_str()) {
            anyhow::bail!(
                "API-spec restore contains duplicate plugin id '{}'",
                plugin.id
            );
        }
    }

    for plugin in additional_plugins {
        if plugin.namespace != spec.namespace {
            anyhow::bail!(
                "API-spec restore additional plugin '{}' belongs to namespace '{}', not '{}'",
                plugin.id,
                plugin.namespace,
                spec.namespace
            );
        }
        if plugin.api_spec_id.is_some() {
            anyhow::bail!(
                "API-spec restore additional plugin '{}' is owned by an API spec",
                plugin.id
            );
        }
        validate_api_spec_proxy_plugin_association(plugin, &bundle.proxy.id)?;
        if !inserted_plugin_ids.insert(plugin.id.as_str()) {
            anyhow::bail!(
                "API-spec restore contains overlapping plugin id '{}'",
                plugin.id
            );
        }
    }

    Ok(())
}

/// Prove that an additional hand-owned upstream still present during
/// compensation is the row captured before deletion, rather than a replacement
/// created by an intervening writer after an orphan cascade removed it.
pub(crate) fn validate_api_spec_retained_upstream_identity(
    expected: &Upstream,
    existing: &Upstream,
) -> Result<(), anyhow::Error> {
    if existing.id != expected.id
        || existing.namespace != expected.namespace
        || existing.api_spec_id != expected.api_spec_id
        || existing.created_at != expected.created_at
    {
        anyhow::bail!(
            "API-spec restore additional upstream '{}' does not match its pre-delete identity",
            expected.id
        );
    }
    Ok(())
}

/// User-facing proxy route conflict message shared by preflight and persistence checks.
pub const PROXY_ROUTE_CONFLICT_ERROR: &str =
    "A proxy with overlapping hosts and listen_path already exists";

/// Durable cross-process fence for namespace-scoped config admission.
///
/// Implementations atomically claim a namespace for `owner` and return the
/// claim's persistent monotonic generation, renew only while that owner still
/// holds the unexpired lease, and release only on an exact owner match. Admin
/// validation keeps a process-local mutex as a cheap first tier, while this
/// lease closes races between writable gateway instances that share the same
/// datastore.
#[async_trait]
pub trait NamespaceConfigAdmissionLeaseBackend: Send + Sync {
    async fn try_acquire_namespace_config_admission_lease(
        &self,
        namespace: &str,
        owner: &str,
    ) -> Result<Option<u64>, anyhow::Error>;

    async fn renew_namespace_config_admission_lease(
        &self,
        namespace: &str,
        owner: &str,
    ) -> Result<bool, anyhow::Error>;

    async fn release_namespace_config_admission_lease(
        &self,
        namespace: &str,
        owner: &str,
    ) -> Result<bool, anyhow::Error>;
}

/// Stable admin-facing message for a namespace mutation that could not enter
/// the datastore-backed admission critical section. Backend/topology details
/// stay in server logs and the chained error only.
pub const MTLS_DNS_ADMISSION_UNAVAILABLE_MESSAGE: &str =
    "Namespace mutation is temporarily unavailable; retry later";

/// Marker for transient namespace-admission contention.
///
/// This is distinct from [`MtlsDnsIdentityConflict`]: contention means the
/// caller should retry the same request later (HTTP 503), while an identity
/// conflict means the candidate itself must change (HTTP 409).
#[derive(Debug)]
pub struct MtlsDnsAdmissionUnavailable;

impl std::fmt::Display for MtlsDnsAdmissionUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(MTLS_DNS_ADMISSION_UNAVAILABLE_MESSAGE)
    }
}

impl std::error::Error for MtlsDnsAdmissionUnavailable {}

pub fn is_mtls_dns_admission_unavailable(error: &anyhow::Error) -> bool {
    error.is::<MtlsDnsAdmissionUnavailable>()
}

// External tests reach this through the lib target's `_test_support` shim;
// the bin target recompiles this module without that caller.
#[allow(dead_code)]
pub(crate) fn mark_mtls_dns_admission_unavailable(error: anyhow::Error) -> anyhow::Error {
    error.context(MtlsDnsAdmissionUnavailable)
}

/// Whether a batch owns its namespace admission guard and whether it runs
/// normal namespace candidate validation (mTLS DNS plus guarded plugin-graph
/// contracts).
///
/// `RestoreRollbackReplay` is intentionally narrow: it may only replay the
/// exact raw snapshot captured immediately before a destructive restore. That
/// snapshot can contain a pre-existing ambiguity the normal runtime rejects,
/// so validating it during rollback could destroy the operator's prior state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchConfigWriteMode {
    Admission,
    GuardedAdmission { guard_owner: String },
    RestoreRollbackReplay { guard_owner: String },
}

impl BatchConfigWriteMode {
    pub(crate) fn validates_mtls_dns(&self) -> bool {
        matches!(self, Self::Admission | Self::GuardedAdmission { .. })
    }

    pub(crate) fn guard_owner(&self) -> Option<&str> {
        match self {
            Self::Admission => None,
            Self::GuardedAdmission { guard_owner }
            | Self::RestoreRollbackReplay { guard_owner } => Some(guard_owner),
        }
    }
}

/// A datastore-serialized candidate would make an effective `mtls_auth`
/// `san_dns` policy ambiguous under ASCII case folding.
///
/// Persistence implementations carry this typed error through their normal
/// transaction/lease boundary so the admin API can return a conflict without
/// exposing unrelated database details. The identities themselves are not
/// secrets, but callers should still prefer the validation messages already
/// produced by [`GatewayConfig::validate_unique_mtls_dns_identities`].
#[derive(Debug)]
pub struct MtlsDnsIdentityConflict {
    errors: Vec<String>,
}

impl MtlsDnsIdentityConflict {
    pub fn new(errors: Vec<String>) -> Self {
        Self { errors }
    }
}

impl std::fmt::Display for MtlsDnsIdentityConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mTLS DNS identity conflict: {}", self.errors.join("; "))
    }
}

impl std::error::Error for MtlsDnsIdentityConflict {}

pub fn is_mtls_dns_identity_conflict(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<MtlsDnsIdentityConflict>())
}

/// Borrow the typed conflict itself so responders can render *its* `Display`
/// rather than the anyhow chain's outermost message. Classification matches
/// anywhere in the chain, so rendering the outermost error would echo any
/// driver-provided context a future caller attaches above the conflict.
pub fn mtls_dns_identity_conflict(error: &anyhow::Error) -> Option<&MtlsDnsIdentityConflict> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<MtlsDnsIdentityConflict>())
}

/// A datastore-serialized candidate would leave an enabled
/// `tcp_connection_throttle` attached only to unsupported protocols (global
/// scope) or directly attached to an unsupported proxy (proxy/proxy-group
/// scope).
///
/// Persistence implementations carry this typed error through the namespace
/// admission lock/lease so admin handlers can return the same validation
/// response as their optimistic preflight without exposing database details.
#[derive(Debug)]
pub struct TcpConnectionThrottleAttachmentConflict {
    errors: Vec<String>,
}

impl TcpConnectionThrottleAttachmentConflict {
    pub fn new(errors: Vec<String>) -> Self {
        Self { errors }
    }

    pub fn errors(&self) -> &[String] {
        &self.errors
    }
}

impl std::fmt::Display for TcpConnectionThrottleAttachmentConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tcp_connection_throttle attachment validation failed: {}",
            self.errors.join("; ")
        )
    }
}

impl std::error::Error for TcpConnectionThrottleAttachmentConflict {}

pub fn tcp_connection_throttle_attachment_conflict(
    error: &anyhow::Error,
) -> Option<&TcpConnectionThrottleAttachmentConflict> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<TcpConnectionThrottleAttachmentConflict>())
}

// ---------------------------------------------------------------------------
// ApiSpec list filter types (Wave 5)
// ---------------------------------------------------------------------------

/// Sort column for `list_api_specs`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ApiSpecSortBy {
    /// `updated_at` — default, most recent first.
    #[default]
    UpdatedAt,
    Title,
    OperationCount,
    CreatedAt,
}

/// Sort direction for `list_api_specs`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SortOrder {
    /// Descending — default (most recent first for timestamps).
    #[default]
    Desc,
    Asc,
}

/// Filter parameters for `list_api_specs`.
#[derive(Debug, Clone)]
pub struct ApiSpecListFilter {
    /// Exact match on `proxy_id`.
    pub proxy_id: Option<String>,
    /// Prefix match on `spec_version` (e.g. `"3.1"` matches `"3.1.0"`, `"3.1.1"`).
    pub spec_version_prefix: Option<String>,
    /// Case-insensitive substring match on `title`.
    pub title_contains: Option<String>,
    /// `updated_at >= ?`
    pub updated_since: Option<DateTime<Utc>>,
    /// Exact tag membership (tag name must appear in the stored JSON array).
    pub has_tag: Option<String>,
    /// Column to sort by (default: `UpdatedAt`).
    pub sort_by: ApiSpecSortBy,
    /// Sort direction (default: `Desc`).
    pub order: SortOrder,
    /// Maximum number of rows to return (default 50, max 200).
    pub limit: u32,
    /// Row offset for pagination (default 0).
    pub offset: u32,
}

impl Default for ApiSpecListFilter {
    fn default() -> Self {
        Self {
            proxy_id: None,
            spec_version_prefix: None,
            title_contains: None,
            updated_since: None,
            has_tag: None,
            sort_by: ApiSpecSortBy::default(),
            order: SortOrder::default(),
            limit: 50,
            offset: 0,
        }
    }
}

/// Namespace-qualified key for resources whose IDs are only unique per namespace.
///
/// Used for incremental removals across every resource type so a misrouted or
/// adversarial delta cannot delete a same-id object in another namespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct NamespacedResourceId {
    pub namespace: String,
    pub id: String,
}

impl NamespacedResourceId {
    pub fn new(namespace: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            id: id.into(),
        }
    }
}

impl std::fmt::Display for NamespacedResourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.namespace, self.id)
    }
}

/// Result of an incremental config poll.
///
/// Contains only resources referenced by durable change-log records newer than
/// the caller's sequence cursor, plus keys of resources that were deleted.
/// Consumer mutations are the exception: loaders return
/// [`IncrementalFullReloadRequired`] so previously quarantined credentials can
/// be rehydrated from storage. The polling loop advances `sequence_cursor` only
/// after the delta validates and applies, so rejected deltas are retried from
/// the same durable point.
///
/// Serializable for CP-to-DP gRPC delta broadcasts. Removal keys are
/// namespace-qualified for every resource type in memory. The JSON encoding is
/// deliberately backward/forward compatible across same-major.minor CP/DP peers
/// (additive `removed_*_keys` alongside the historical bare-ID arrays); see the
/// wire-compatibility note above the serde impls below.
#[derive(Clone)]
pub struct IncrementalResult {
    pub added_or_modified_proxies: Vec<Proxy>,
    pub removed_proxy_ids: Vec<NamespacedResourceId>,
    pub added_or_modified_consumers: Vec<Consumer>,
    pub removed_consumer_ids: Vec<NamespacedResourceId>,
    pub added_or_modified_plugin_configs: Vec<PluginConfig>,
    pub removed_plugin_config_ids: Vec<NamespacedResourceId>,
    pub added_or_modified_upstreams: Vec<Upstream>,
    pub removed_upstream_ids: Vec<NamespacedResourceId>,
    /// Highest durable config change sequence included in this poll.
    ///
    /// Optional on the wire (`#[serde(default)]` on the decode struct) so a
    /// peer that predates the cursor still produces a parseable delta.
    pub sequence_cursor: u64,
    /// Timestamp to use as the in-memory/gRPC config version for this delta.
    pub poll_timestamp: DateTime<Utc>,
}

// Rolling-upgrade JSON encoding of `IncrementalResult`.
//
// The delta body travels as `ConfigUpdate.config_json`, so its JSON shape is a
// same-major.minor compatibility contract (`docs/upgrade_guide.md` promises a
// CP-first rollout with patch-mixed CP/DP fleets). Namespace-qualified removal
// keys are therefore ADDITIVE: `removed_*_keys` carry `(namespace, id)` objects
// for peers that understand them, while the historical `removed_proxy_ids` /
// `removed_plugin_config_ids` / `removed_upstream_ids` arrays keep their
// bare-string shape so a peer that predates qualified removals still parses the
// body and ignores the additive arrays. `removed_consumer_ids` keeps the object
// shape it already had on this major.minor.
//
// Decoding accepts either shape in every removal array. A bare string carries no
// namespace, so it decodes with an empty namespace and must be qualified with
// the already-authorized subscription namespace through
// `IncrementalResult::qualify_unqualified_removals` before apply. Anything still
// unqualified is dropped by the DP namespace filter, so a legacy-shaped delta
// can never reach another tenant's resources.

/// One removal entry as it may appear on the wire: a namespace-qualified object
/// from a current peer, or a bare ID string from a peer that predates them.
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum RemovalKeyWire {
    Qualified(NamespacedResourceId),
    LegacyBareId(String),
}

impl RemovalKeyWire {
    fn into_key(self) -> NamespacedResourceId {
        match self {
            RemovalKeyWire::Qualified(key) => key,
            // Empty namespace marks "unqualified"; the DP replaces it with its
            // own authorized subscription namespace before applying.
            RemovalKeyWire::LegacyBareId(id) => NamespacedResourceId {
                namespace: String::new(),
                id,
            },
        }
    }
}

fn merge_removal_keys(
    qualified: Vec<NamespacedResourceId>,
    legacy: Vec<RemovalKeyWire>,
) -> Vec<NamespacedResourceId> {
    if qualified.is_empty() {
        legacy.into_iter().map(RemovalKeyWire::into_key).collect()
    } else {
        qualified
    }
}

fn legacy_removal_ids(keys: &[NamespacedResourceId]) -> Vec<&str> {
    keys.iter().map(|key| key.id.as_str()).collect()
}

#[derive(serde::Serialize)]
struct IncrementalResultSer<'a> {
    added_or_modified_proxies: &'a [Proxy],
    removed_proxy_ids: Vec<&'a str>,
    removed_proxy_keys: &'a [NamespacedResourceId],
    added_or_modified_consumers: &'a [Consumer],
    removed_consumer_ids: &'a [NamespacedResourceId],
    added_or_modified_plugin_configs: &'a [PluginConfig],
    removed_plugin_config_ids: Vec<&'a str>,
    removed_plugin_config_keys: &'a [NamespacedResourceId],
    added_or_modified_upstreams: &'a [Upstream],
    removed_upstream_ids: Vec<&'a str>,
    removed_upstream_keys: &'a [NamespacedResourceId],
    sequence_cursor: u64,
    poll_timestamp: DateTime<Utc>,
}

#[derive(serde::Deserialize)]
struct IncrementalResultDe {
    added_or_modified_proxies: Vec<Proxy>,
    removed_proxy_ids: Vec<RemovalKeyWire>,
    #[serde(default)]
    removed_proxy_keys: Vec<NamespacedResourceId>,
    added_or_modified_consumers: Vec<Consumer>,
    removed_consumer_ids: Vec<RemovalKeyWire>,
    added_or_modified_plugin_configs: Vec<PluginConfig>,
    removed_plugin_config_ids: Vec<RemovalKeyWire>,
    #[serde(default)]
    removed_plugin_config_keys: Vec<NamespacedResourceId>,
    added_or_modified_upstreams: Vec<Upstream>,
    removed_upstream_ids: Vec<RemovalKeyWire>,
    #[serde(default)]
    removed_upstream_keys: Vec<NamespacedResourceId>,
    #[serde(default)]
    sequence_cursor: u64,
    poll_timestamp: DateTime<Utc>,
}

impl serde::Serialize for IncrementalResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde::Serialize::serialize(
            &IncrementalResultSer {
                added_or_modified_proxies: &self.added_or_modified_proxies,
                removed_proxy_ids: legacy_removal_ids(&self.removed_proxy_ids),
                removed_proxy_keys: &self.removed_proxy_ids,
                added_or_modified_consumers: &self.added_or_modified_consumers,
                removed_consumer_ids: &self.removed_consumer_ids,
                added_or_modified_plugin_configs: &self.added_or_modified_plugin_configs,
                removed_plugin_config_ids: legacy_removal_ids(&self.removed_plugin_config_ids),
                removed_plugin_config_keys: &self.removed_plugin_config_ids,
                added_or_modified_upstreams: &self.added_or_modified_upstreams,
                removed_upstream_ids: legacy_removal_ids(&self.removed_upstream_ids),
                removed_upstream_keys: &self.removed_upstream_ids,
                sequence_cursor: self.sequence_cursor,
                poll_timestamp: self.poll_timestamp,
            },
            serializer,
        )
    }
}

impl<'de> serde::Deserialize<'de> for IncrementalResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = IncrementalResultDe::deserialize(deserializer)?;
        Ok(IncrementalResult {
            added_or_modified_proxies: wire.added_or_modified_proxies,
            removed_proxy_ids: merge_removal_keys(wire.removed_proxy_keys, wire.removed_proxy_ids),
            added_or_modified_consumers: wire.added_or_modified_consumers,
            // Consumers have no additive `*_keys` array: their canonical wire
            // shape on this major.minor is already the qualified object, and
            // decoding still tolerates an older peer's bare-ID strings.
            removed_consumer_ids: wire
                .removed_consumer_ids
                .into_iter()
                .map(RemovalKeyWire::into_key)
                .collect(),
            added_or_modified_plugin_configs: wire.added_or_modified_plugin_configs,
            removed_plugin_config_ids: merge_removal_keys(
                wire.removed_plugin_config_keys,
                wire.removed_plugin_config_ids,
            ),
            added_or_modified_upstreams: wire.added_or_modified_upstreams,
            removed_upstream_ids: merge_removal_keys(
                wire.removed_upstream_keys,
                wire.removed_upstream_ids,
            ),
            sequence_cursor: wire.sequence_cursor,
            poll_timestamp: wire.poll_timestamp,
        })
    }
}

impl IncrementalResult {
    /// Adopt the authorized subscription namespace for removal keys that a peer
    /// sent as bare IDs (see the wire-compatibility note above the serde impls).
    ///
    /// A CP that predates namespace-qualified removals sends bare resource IDs,
    /// which decode with an empty namespace. The subscribing DP is authorized
    /// for exactly one namespace, so adopting that namespace reproduces the
    /// legacy semantics without widening reach — the DP's namespace filter still
    /// drops every key outside it, so the cross-namespace deletion guarantee is
    /// unaffected.
    ///
    /// Returns how many keys were qualified; a peer that sent qualified keys
    /// yields `0`.
    pub fn qualify_unqualified_removals(&mut self, namespace: &str) -> usize {
        fn qualify(keys: &mut [NamespacedResourceId], namespace: &str) -> usize {
            let mut qualified = 0;
            for key in keys {
                if key.namespace.is_empty() {
                    key.namespace = namespace.to_string();
                    qualified += 1;
                }
            }
            qualified
        }

        qualify(&mut self.removed_proxy_ids, namespace)
            + qualify(&mut self.removed_consumer_ids, namespace)
            + qualify(&mut self.removed_plugin_config_ids, namespace)
            + qualify(&mut self.removed_upstream_ids, namespace)
    }

    /// True when nothing changed — skip all cache work.
    pub fn is_empty(&self) -> bool {
        self.added_or_modified_proxies.is_empty()
            && self.removed_proxy_ids.is_empty()
            && self.added_or_modified_consumers.is_empty()
            && self.removed_consumer_ids.is_empty()
            && self.added_or_modified_plugin_configs.is_empty()
            && self.removed_plugin_config_ids.is_empty()
            && self.added_or_modified_upstreams.is_empty()
            && self.removed_upstream_ids.is_empty()
    }
}

/// Marker returned by an incremental loader when a consumer mutation must be
/// applied from an authoritative full snapshot.
///
/// Runtime HMAC quarantine deliberately removes invalid credentials from the
/// published config. Patching a later consumer-only delta onto that sanitized
/// snapshot cannot restore a different consumer whose stored credential was
/// previously stripped. Consumer creates, updates, and deletes therefore
/// escalate to the poller's existing same-tick full-reload path, which reloads
/// every stored consumer before applying quarantine again.
#[derive(Debug)]
pub struct IncrementalFullReloadRequired {
    namespace: String,
}

impl IncrementalFullReloadRequired {
    pub(crate) fn for_consumer_changes(namespace: &str) -> Self {
        Self {
            namespace: namespace.to_string(),
        }
    }
}

impl std::fmt::Display for IncrementalFullReloadRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "consumer changes in namespace '{}' require an authoritative full reload to rehydrate quarantined credentials",
            self.namespace
        )
    }
}

impl std::error::Error for IncrementalFullReloadRequired {}

/// Whether an incremental-load error is the expected consumer-change
/// escalation rather than a database connectivity or query failure.
pub fn is_incremental_full_reload_required(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<IncrementalFullReloadRequired>())
}

/// Result of a paginated database query.
pub struct PaginatedResult<T> {
    pub items: Vec<T>,
    pub total: i64,
}

/// Connection pool statistics for observability.
///
/// Exposed via the admin `/status` endpoint to help operators tune pool settings.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DbPoolStats {
    /// Current number of connections managed by the pool (idle + active).
    pub size: u32,
    /// Number of idle connections available for checkout.
    pub idle: u32,
    /// Number of connections currently checked out (in-use).
    pub active: u32,
    /// Maximum configured connections (`FERRUM_DB_POOL_MAX_CONNECTIONS`).
    pub max_connections: u32,
    /// Minimum configured idle connections (`FERRUM_DB_POOL_MIN_CONNECTIONS`).
    pub min_connections: u32,
    /// Read replica pool stats, if a configured admin-read replica is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_replica: Option<Box<DbPoolStatsInner>>,
}

/// Inner pool stats (used for read replicas to avoid infinite nesting).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DbPoolStatsInner {
    pub size: u32,
    pub idle: u32,
    pub active: u32,
}

/// Atomicity mode used by a namespace-wide resource clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteMode {
    Atomic,
    NonAtomic,
}

/// Authoritative resource counts used to classify an ambiguous atomic clear.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NamespaceResourceCounts {
    pub proxies: u64,
    pub consumers: u64,
    pub plugin_configs: u64,
    pub upstreams: u64,
    pub api_specs: u64,
}

impl NamespaceResourceCounts {
    pub fn is_empty(self) -> bool {
        self == Self::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicClearVerification {
    ClearCommitted,
    PriorCountsStillVisible,
    UnknownOutcome,
}

impl AtomicClearVerification {
    /// Whether the namespace guard must remain retained after verification.
    /// Fail closed for every result except a definitively committed clear.
    pub fn requires_guard_retention(self) -> bool {
        !matches!(self, Self::ClearCommitted)
    }
}

pub fn classify_atomic_clear_verification<E>(
    prior: NamespaceResourceCounts,
    verification: Result<NamespaceResourceCounts, E>,
) -> AtomicClearVerification {
    match verification {
        // Matching the prior snapshot only proves the clear was not visible to
        // this read. An UnknownTransactionCommitResult may still commit later
        // on another pooled connection, so this is not a definitive abort.
        Ok(post_clear) if post_clear == prior => AtomicClearVerification::PriorCountsStillVisible,
        Ok(post_clear) if post_clear.is_empty() => AtomicClearVerification::ClearCommitted,
        Ok(_) | Err(_) => AtomicClearVerification::UnknownOutcome,
    }
}

/// A row/document that exists but cannot be decoded into its resource type.
///
/// The display text is intentionally safe for admin responses: it identifies
/// the resource without including serialized row contents or credential data.
#[derive(Debug)]
pub struct SnapshotDataIntegrityError {
    resource_type: &'static str,
    resource_id: Option<String>,
    source: anyhow::Error,
}

impl SnapshotDataIntegrityError {
    pub fn new(
        resource_type: &'static str,
        resource_id: Option<String>,
        source: anyhow::Error,
    ) -> Self {
        Self {
            resource_type,
            resource_id,
            source,
        }
    }
}

impl std::fmt::Display for SnapshotDataIntegrityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.resource_id.as_deref() {
            Some(id) => write!(
                formatter,
                "data-integrity failure decoding {} resource '{}'",
                self.resource_type, id
            ),
            None => write!(
                formatter,
                "data-integrity failure decoding {} resource (id unavailable)",
                self.resource_type
            ),
        }
    }
}

impl std::error::Error for SnapshotDataIntegrityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl DeleteMode {
    pub fn is_atomic(self) -> bool {
        matches!(self, Self::Atomic)
    }
}

/// A failed namespace clear, coupled to the exact mode that executed it.
#[derive(Debug)]
pub struct DeleteAllResourcesError {
    mode: DeleteMode,
    unknown_commit_result: bool,
    source: anyhow::Error,
}

impl DeleteAllResourcesError {
    pub fn new(mode: DeleteMode, source: anyhow::Error) -> Self {
        Self {
            mode,
            unknown_commit_result: false,
            source,
        }
    }

    pub fn with_unknown_commit_result(mode: DeleteMode, source: anyhow::Error) -> Self {
        Self {
            mode,
            unknown_commit_result: true,
            source,
        }
    }

    pub fn mode(&self) -> DeleteMode {
        self.mode
    }

    pub fn has_unknown_commit_result(&self) -> bool {
        self.unknown_commit_result
    }
}

impl std::fmt::Display for DeleteAllResourcesError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for DeleteAllResourcesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Why a full configuration is being loaded.
///
/// Only runtime loads are immediately followed by a `PluginCache` build, so
/// only they may validate node-local plugin files and retain their immutable
/// snapshots for that build. Control-plane distribution and backup exports
/// validate portable configuration only; opening a data-plane-local MMDB there
/// would waste up to the full aggregate budget and leave no cache consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FullConfigLoadPurpose {
    Runtime,
    ControlPlane,
    BackupExport,
}

impl FullConfigLoadPurpose {
    pub fn loads_node_local_plugin_files(self) -> bool {
        matches!(self, Self::Runtime)
    }
}

/// Unified database backend trait.
///
/// This trait defines all operations needed by the admin API, operating modes,
/// and config polling. Concrete implementations exist for:
/// - `DatabaseStore` (sqlx) — PostgreSQL, MySQL, SQLite
/// - `MongoStore` (mongodb) — MongoDB
///
/// Connection lifecycle (connect, reconnect, failover) is NOT in the trait
/// because construction is inherently backend-specific. The trait covers only
/// operations on an already-connected store.
#[allow(dead_code)] // Some methods are only used through dyn dispatch or by MongoDB backend
#[async_trait]
pub trait DatabaseBackend: NamespaceConfigAdmissionLeaseBackend + Send + Sync {
    // -----------------------------------------------------------------------
    // Health & metadata
    // -----------------------------------------------------------------------

    /// Run a lightweight health check (e.g. `SELECT 1` for SQL, `ping` for MongoDB).
    async fn health_check(&self) -> Result<(), anyhow::Error>;

    /// Return the database type identifier (e.g. "postgres", "mysql", "sqlite", "mongodb").
    fn db_type(&self) -> &str;

    /// Returns true if a read replica is configured.
    fn has_read_replica(&self) -> bool;

    /// Returns true if a configured read replica currently has an active pool.
    fn read_replica_available(&self) -> bool {
        self.has_read_replica()
    }

    /// Returns true when a configured read replica is intentionally suppressed
    /// rather than broken — e.g. the SQL store is serving on a failover
    /// topology and the replica belongs to the (currently unavailable) primary
    /// topology. A suppressed replica reports `read_replica_available() ==
    /// false`, but the poll scheduler MUST NOT treat it as a pool to repair:
    /// reconnecting it every cycle can never converge while admin reads stay on
    /// the failover pool. It becomes eligible again on primary failback.
    fn read_replica_suppressed(&self) -> bool {
        false
    }

    /// Return connection pool statistics for observability.
    ///
    /// Returns `None` when the backend does not expose pool internals
    /// (e.g. MongoDB, whose driver manages pooling internally).
    fn pool_stats(&self) -> Option<DbPoolStats> {
        None
    }

    // -----------------------------------------------------------------------
    // Settings (mutable — called once at startup before sharing via Arc)
    // -----------------------------------------------------------------------

    /// Set the slow query threshold (in milliseconds).
    fn set_slow_query_threshold(&mut self, threshold_ms: Option<u64>);

    /// Set the maximum rows fetched per query during full config loading.
    /// Only meaningful for SQL backends; MongoDB uses cursor-based loading.
    fn set_full_load_page_size(&mut self, page_size: u64);

    /// Set the certificate expiry warning threshold (days before expiration).
    fn set_cert_expiry_warning_days(&mut self, days: u64);

    /// Set the backend IP allowlist policy for SSRF protection.
    fn set_backend_allow_ips(&mut self, policy: crate::config::BackendEgressPolicy);

    // -----------------------------------------------------------------------
    // Full config loading
    // -----------------------------------------------------------------------

    /// Load the full gateway configuration for a specific consumer.
    async fn load_full_config_for_purpose(
        &self,
        namespace: &str,
        purpose: FullConfigLoadPurpose,
    ) -> Result<GatewayConfig, anyhow::Error>;

    /// Load a runtime configuration that will immediately build proxy caches.
    async fn load_full_config(&self, namespace: &str) -> Result<GatewayConfig, anyhow::Error> {
        self.load_full_config_for_purpose(namespace, FullConfigLoadPurpose::Runtime)
            .await
    }

    /// Load a namespace's resources for a rollback snapshot WITHOUT running the
    /// semantic validation pipeline that [`load_full_config`](Self::load_full_config)
    /// applies.
    ///
    /// Restore captures the prior state with this before its destructive clear.
    /// A rollback snapshot only needs the current rows in order to restore them,
    /// not validation — so an *invalid-but-present* config (exactly what an
    /// operator runs restore to *repair*) is still captured, keeping rollback
    /// available during the repair. A genuine connectivity/timeout failure, by
    /// contrast, surfaces as `Err`, letting the caller ABORT the destructive
    /// restore instead of wiping a config that was merely transiently
    /// unreachable.
    ///
    /// Reads MUST come from the authoritative primary — a rollback snapshot must
    /// never be built from a possibly-stale read replica. `api_spec_id` ownership
    /// tags are cleared (mirroring `load_full_config`): a rollback re-applies the
    /// config resources as hand-managed, and the `api_specs` rows themselves are
    /// captured separately by the caller.
    async fn load_namespace_snapshot(
        &self,
        namespace: &str,
    ) -> Result<GatewayConfig, anyhow::Error>;

    /// Count namespace resources on the authoritative primary without
    /// deserializing rows/documents.
    async fn count_namespace_resources(
        &self,
        namespace: &str,
    ) -> Result<NamespaceResourceCounts, anyhow::Error>;

    // -----------------------------------------------------------------------
    // Incremental polling
    // -----------------------------------------------------------------------

    /// Return the highest durable config-change sequence currently committed
    /// for `namespace`. Callers seed this after a full reload so subsequent
    /// incremental polls start from an authoritative snapshot boundary.
    async fn latest_change_sequence(&self, namespace: &str) -> Result<u64, anyhow::Error>;

    /// Load only resources changed after `after_sequence`.
    async fn load_incremental_config(
        &self,
        namespace: &str,
        after_sequence: u64,
    ) -> Result<IncrementalResult, anyhow::Error>;

    // -----------------------------------------------------------------------
    // Proxy CRUD
    //
    // ID-only reads/deletes/updates are namespace-predicated at the query
    // level (issue #2122 DB-M1): the tenant boundary is enforced by the
    // WHERE clause / filter document itself, not by a post-read comparison
    // in the caller. `update_*` returns `Ok(false)` when no row/document
    // matched `(namespace, id)` (issue #2122 DB-M4) so a PUT racing a
    // concurrent delete surfaces as not-found instead of a phantom success;
    // implementations must not emit a config-change record in that case.
    // -----------------------------------------------------------------------

    async fn create_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error>;
    async fn update_proxy(&self, proxy: &Proxy) -> Result<bool, anyhow::Error>;
    async fn delete_proxy(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error>;
    async fn get_proxy(&self, namespace: &str, id: &str) -> Result<Option<Proxy>, anyhow::Error>;
    /// Load an existing proxy for write prechecks/audit without rejecting
    /// repairable proxy-plugin reference corruption. Backends that store
    /// associations inline can use the normal read path.
    async fn get_proxy_for_write(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<Proxy>, anyhow::Error> {
        self.get_proxy(namespace, id).await
    }
    /// Check whether a proxy with the given ID exists in `namespace`.
    /// Returns `true` only when the row is in the requested namespace, so
    /// admin-side reference checks cannot be satisfied by a row that lives
    /// in a different namespace.
    async fn check_proxy_exists(
        &self,
        proxy_id: &str,
        namespace: &str,
    ) -> Result<bool, anyhow::Error>;
    /// Return a stable, backend-paginated proxy page and the namespace total.
    /// Callers must pass a positive bounded `limit` and an `offset` in
    /// `0..=i64::MAX`; admin callers satisfy this through validated pagination.
    async fn list_proxies_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Proxy>, anyhow::Error>;

    // -----------------------------------------------------------------------
    // Consumer CRUD
    // -----------------------------------------------------------------------

    async fn create_consumer(&self, consumer: &Consumer) -> Result<(), anyhow::Error>;
    /// `mode` lets a multi-step credential or restore operation borrow the
    /// namespace guard it acquired before its authoritative read.
    async fn update_consumer(
        &self,
        consumer: &Consumer,
        mode: &BatchConfigWriteMode,
    ) -> Result<bool, anyhow::Error>;
    async fn delete_consumer(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error>;
    async fn get_consumer(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<Consumer>, anyhow::Error>;
    /// Return a stable, backend-paginated consumer page and the namespace total.
    /// Callers must pass a positive bounded `limit` and an `offset` in
    /// `0..=i64::MAX`; admin callers satisfy this through validated pagination.
    async fn list_consumers_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Consumer>, anyhow::Error>;

    // -----------------------------------------------------------------------
    // Plugin config CRUD
    // -----------------------------------------------------------------------

    async fn create_plugin_config(&self, pc: &PluginConfig) -> Result<(), anyhow::Error>;
    async fn update_plugin_config(&self, pc: &PluginConfig) -> Result<bool, anyhow::Error>;
    async fn delete_plugin_config(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error>;
    async fn get_plugin_config(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<PluginConfig>, anyhow::Error>;
    /// Return a stable, backend-paginated plugin-config page and namespace total.
    /// Callers must pass a positive bounded `limit` and an `offset` in
    /// `0..=i64::MAX`; admin callers satisfy this through validated pagination.
    async fn list_plugin_configs_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<PluginConfig>, anyhow::Error>;

    // -----------------------------------------------------------------------
    // Upstream CRUD
    // -----------------------------------------------------------------------

    async fn create_upstream(&self, upstream: &Upstream) -> Result<(), anyhow::Error>;
    async fn update_upstream(&self, upstream: &Upstream) -> Result<bool, anyhow::Error>;
    async fn delete_upstream(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error>;
    async fn get_upstream(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<Upstream>, anyhow::Error>;
    async fn cleanup_orphaned_upstream(
        &self,
        namespace: &str,
        upstream_id: &str,
    ) -> Result<(), anyhow::Error>;
    /// Return a stable, backend-paginated upstream page and the namespace total.
    /// Callers must pass a positive bounded `limit` and an `offset` in
    /// `0..=i64::MAX`; admin callers satisfy this through validated pagination.
    async fn list_upstreams_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Upstream>, anyhow::Error>;

    // -----------------------------------------------------------------------
    // Validation queries
    // -----------------------------------------------------------------------

    /// Returns `true` when the `(listen_path, hosts)` combination does not
    /// conflict with any existing proxy in `namespace`.
    ///
    /// Conflict semantics:
    /// - `Some(path) + non-empty hosts` — conflict with any existing proxy with
    ///   the same `listen_path` AND overlapping hosts (empty hosts on the
    ///   existing row counts as catch-all and overlaps with everything).
    /// - `Some(path) + empty hosts` — conflict with any existing proxy with the
    ///   same `listen_path` regardless of hosts.
    /// - `None + non-empty hosts` (host-only proxy) — conflict with any
    ///   existing proxy that has `listen_path IS NULL` AND overlapping hosts.
    /// - `None + empty hosts` — rejected upstream of this call in
    ///   `validate_fields_inner`. Defensive implementations should return an
    ///   error or `Ok(false)` here.
    async fn check_listen_path_unique(
        &self,
        namespace: &str,
        listen_path: Option<&str>,
        hosts: &[String],
        exclude_proxy_id: Option<&str>,
    ) -> Result<bool, anyhow::Error>;

    async fn check_proxy_name_unique(
        &self,
        namespace: &str,
        name: &str,
        exclude_proxy_id: Option<&str>,
    ) -> Result<bool, anyhow::Error>;

    async fn check_upstream_name_unique(
        &self,
        namespace: &str,
        name: &str,
        exclude_upstream_id: Option<&str>,
    ) -> Result<bool, anyhow::Error>;

    async fn check_consumer_identity_unique(
        &self,
        namespace: &str,
        consumer_id: &str,
        username: &str,
        custom_id: Option<&str>,
        exclude_consumer_id: Option<&str>,
    ) -> Result<Option<String>, anyhow::Error>;

    async fn check_keyauth_key_unique(
        &self,
        namespace: &str,
        key: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error>;

    async fn check_mtls_identity_unique(
        &self,
        namespace: &str,
        identity: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error>;

    async fn check_listen_port_unique(
        &self,
        namespace: &str,
        port: u16,
        exclude_proxy_id: Option<&str>,
    ) -> Result<bool, anyhow::Error>;

    /// Check whether an upstream with the given ID exists in `namespace`.
    /// Returns `true` only when the row is in the requested namespace, so a
    /// proxy in namespace A cannot reference an upstream that actually lives
    /// in namespace B (which would silently 502 at runtime).
    async fn check_upstream_exists(
        &self,
        upstream_id: &str,
        namespace: &str,
    ) -> Result<bool, anyhow::Error>;

    /// Validate that a proxy's plugin association list references existing
    /// plugin configs. Plugin configs are looked up only within `namespace`
    /// — references to plugin_configs in other namespaces are rejected as
    /// non-existent so cross-namespace pollution is impossible.
    async fn validate_proxy_plugin_associations(
        &self,
        proxy_id: &str,
        namespace: &str,
        plugins: &[crate::config::types::PluginAssociation],
    ) -> Result<Vec<String>, anyhow::Error>;

    // -----------------------------------------------------------------------
    // Batch operations
    // -----------------------------------------------------------------------

    async fn batch_create_proxies(
        &self,
        proxies: &[Proxy],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error>;
    async fn batch_create_proxies_without_plugins(
        &self,
        proxies: &[Proxy],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error>;
    async fn batch_attach_proxy_plugins(
        &self,
        proxies: &[Proxy],
        mode: &BatchConfigWriteMode,
    ) -> Result<(), anyhow::Error>;
    async fn batch_create_consumers(
        &self,
        consumers: &[Consumer],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error>;
    async fn batch_create_plugin_configs(
        &self,
        configs: &[PluginConfig],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error>;
    async fn batch_create_upstreams(
        &self,
        upstreams: &[Upstream],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error>;
    /// Clear all resources in a namespace and report the mode that actually ran.
    ///
    /// SQL backends run the clear inside a single transaction, so a failure
    /// commits nothing and leaves the prior config fully intact. A replica-set
    /// MongoDB deployment likewise runs it in a transaction. Standalone MongoDB
    /// has no multi-document transactions, so it deletes collections one-by-one
    /// and a mid-clear failure can leave a partially-cleared namespace.
    ///
    /// Failures carry the same mode captured by the operation before it starts,
    /// so a MongoDB reconnect cannot make the caller classify the clear against
    /// a different topology than the one whose branch actually executed.
    async fn delete_all_resources(
        &self,
        namespace: &str,
        mode: &BatchConfigWriteMode,
    ) -> Result<DeleteMode, DeleteAllResourcesError>;

    /// Block namespace resource writers across a multi-step operation. The
    /// opaque owner must be supplied to guarded writes until release.
    async fn acquire_mtls_dns_admission_guard(
        &self,
        namespace: &str,
    ) -> Result<String, anyhow::Error>;

    /// Release only the guard owned by `guard_owner`. An owner mismatch must
    /// fail closed rather than unblocking another operation.
    async fn release_mtls_dns_admission_guard(
        &self,
        namespace: &str,
        guard_owner: &str,
    ) -> Result<(), anyhow::Error>;

    // -----------------------------------------------------------------------
    // Connection lifecycle (called from polling loops)
    // -----------------------------------------------------------------------

    /// Atomically replace the connection pool with a freshly connected one.
    ///
    /// The URL must be the effective URL produced by `EnvConfig`, including any
    /// database TLS parameters derived from `FERRUM_DB_TLS_MODE`.
    async fn reconnect(&self, db_url: &str) -> Result<(), anyhow::Error>;

    /// Atomically replace the admin-read replica pool with a freshly connected one.
    async fn reconnect_read_replica(&self, replica_url: &str) -> Result<(), anyhow::Error>;

    /// Try to reconnect to any available database URL (primary first, then failover).
    async fn try_failover_reconnect(&self, primary_url: &str) -> Result<String, anyhow::Error>;

    /// Run schema migrations (SQL) or ensure indexes/collections exist (MongoDB).
    async fn run_migrations(&self) -> Result<(), anyhow::Error>;

    /// If the backend has pending migrations deferred from offline bootstrap,
    /// try to apply them now. Returns `Ok(true)` if migrations were run, or
    /// `Ok(false)` if nothing was pending (the normal case). `Err` means the
    /// database is still unreachable or the migration itself failed; the
    /// caller should leave the "pending" state unchanged.
    ///
    /// Call this anywhere an outcome-agnostic migration check is cheap: at
    /// startup after offline bootstrap, on each polling-loop success, and
    /// at the end of `reconnect()`. Implementations must be idempotent —
    /// concurrent calls should not run migrations twice.
    ///
    /// The default implementation is a no-op for backends that don't have
    /// an offline-bootstrap / lazy-pool concept (e.g., MongoDB).
    async fn maybe_apply_deferred_migrations(&self) -> Result<bool, anyhow::Error> {
        Ok(false)
    }

    /// Return the list of custom-plugin migrations that have not yet been
    /// applied to the database. Used at startup to warn operators when a
    /// gateway upgrade brings in new plugin schema changes that have not yet
    /// been applied.
    ///
    /// The default implementation returns an empty list — appropriate for
    /// backends that do not support SQL-based plugin migrations (e.g.,
    /// MongoDB; per the docs, `CustomPluginMigration` is SQL-only and
    /// MongoDB plugins create collections/indexes inside `create_plugin()`).
    async fn pending_plugin_migrations(
        &self,
        _plugin_migrations: &[(&str, Vec<crate::config::migrations::CustomPluginMigration>)],
    ) -> Result<Vec<crate::config::migrations::PendingPluginMigration>, anyhow::Error> {
        Ok(Vec::new())
    }

    /// Apply all pending custom-plugin migrations. Used by the opt-in
    /// `FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS=true` startup path so operators
    /// can ship a binary upgrade with bundled plugin schema changes without
    /// running a separate `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up`
    /// step.
    ///
    /// The default implementation is a no-op for backends that do not
    /// support SQL-based plugin migrations (e.g., MongoDB).
    async fn apply_plugin_migrations(
        &self,
        _plugin_migrations: &[(&str, Vec<crate::config::migrations::CustomPluginMigration>)],
    ) -> Result<Vec<crate::config::migrations::PluginMigrationRecord>, anyhow::Error> {
        Ok(Vec::new())
    }

    /// Return all distinct namespaces across all resource tables for admin reads.
    async fn list_namespaces(&self) -> Result<Vec<String>, anyhow::Error>;

    /// Return all distinct namespaces using the authoritative primary read path.
    ///
    /// Runtime config polling uses this when `FERRUM_CP_NAMESPACES=*` so namespace
    /// discovery cannot lag behind primary resource reads.
    async fn list_namespaces_authoritative(&self) -> Result<Vec<String>, anyhow::Error> {
        self.list_namespaces().await
    }

    /// Return a stable, backend-paginated namespace page and the total
    /// namespace count, ordered ascending by namespace name.
    /// Callers must pass a positive bounded `limit` and an `offset` in
    /// `0..=i64::MAX`; admin callers satisfy this through validated pagination.
    async fn list_namespaces_paginated(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<String>, anyhow::Error>;

    // -----------------------------------------------------------------------
    // ApiSpec CRUD (admin-only — NEVER call from polling loops, gRPC
    // distribution, or GatewayConfig loading. Hot-path isolation is critical.)
    // -----------------------------------------------------------------------

    /// Atomically insert the api_spec row plus all bundle resources.
    ///
    /// Insertion order: upstream (optional) → proxy → plugin_configs → api_spec.
    /// All four resource kinds are tagged with `api_spec_id = spec.id`.
    ///
    /// Returns `Err` if any unique constraint is violated (e.g. duplicate proxy
    /// id or duplicate `(namespace, proxy_id)` on api_specs). Wave 3 handlers
    /// map constraint violations to HTTP 409.
    async fn submit_api_spec_bundle(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &ApiSpec,
    ) -> Result<(), anyhow::Error>;

    /// Atomically restore a deleted API spec together with upstreams and
    /// non-spec-owned plugins affected by the proxy delete cascade. A
    /// hand-owned additional upstream that remained live through the delete
    /// is preserved rather than inserted again.
    ///
    /// SQL backends and replica-set MongoDB implement this transactionally for
    /// database and control-plane modes. A backend/topology without a
    /// multi-document transaction must return an error before its first write;
    /// data-plane and file modes have no writable database path. Recovery-time
    /// plugin construction must use `validation_http_client`, which is the same
    /// configured egress-policy and real-IP client used by admin admission.
    async fn restore_api_spec_bundle(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &ApiSpec,
        additional_upstreams: &[Upstream],
        additional_plugins: &[PluginConfig],
        validation_http_client: &PluginHttpClient,
    ) -> Result<(), anyhow::Error>;

    /// Atomically replace an existing api spec identified by `spec.id`.
    ///
    /// Deletes the spec-owned resources (those whose `api_spec_id = spec.id`),
    /// then inserts the new bundle in their place, and updates the api_spec row.
    /// Resources not owned by the spec (e.g. hand-added plugins whose
    /// `api_spec_id` is NULL) are left untouched.
    async fn replace_api_spec_bundle(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &ApiSpec,
    ) -> Result<(), anyhow::Error>;

    /// Fetch a single ApiSpec by namespace + id.
    async fn get_api_spec(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<ApiSpec>, anyhow::Error>;

    /// Fetch the ApiSpec that owns a given proxy (by proxy_id), if any.
    async fn get_api_spec_by_proxy(
        &self,
        namespace: &str,
        proxy_id: &str,
    ) -> Result<Option<ApiSpec>, anyhow::Error>;

    /// List ApiSpecs in a namespace, with filtering, sorting, and pagination.
    ///
    /// This is a summary path: implementations must not hydrate the
    /// `spec_content` blob for each row. Returned items carry empty
    /// `spec_content`; callers that need the original document must use
    /// `get_api_spec` or `get_api_spec_by_proxy`.
    ///
    /// Default sort is `updated_at DESC` (most recent first).
    /// `filter.limit` and `filter.offset` drive pagination.
    /// The returned [`PaginatedResult`] includes a `total` count of all matching
    /// rows (ignoring limit/offset) so callers can build "showing X of Y" UI.
    async fn list_api_specs(
        &self,
        namespace: &str,
        filter: &ApiSpecListFilter,
    ) -> Result<PaginatedResult<ApiSpec>, anyhow::Error>;

    /// Count ApiSpecs in a namespace using the authoritative primary read path.
    ///
    /// This count-only operation must not fetch or deserialize item metadata.
    async fn count_api_specs(&self, namespace: &str) -> Result<u64, anyhow::Error>;

    /// Delete an ApiSpec and all resources it owns.
    ///
    /// Deletion order: spec-owned plugin_configs and upstreams (manual cleanup
    /// because the `api_spec_id` back-links are not FK-enforced), then the
    /// proxy (whose FK cascade also removes the api_specs row). Returns `true`
    /// if a spec was found and deleted.
    async fn delete_api_spec(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error>;

    /// List the plugin configs owned by a specific api spec (tagged with
    /// `api_spec_id = spec_id`).
    ///
    /// Used by the PUT handler to resolve existing spec-owned plugin IDs so
    /// re-submitted specs with empty plugin IDs can reuse them rather than
    /// minting fresh UUIDs every time.
    ///
    /// Admin-only. NEVER call from polling loops, gRPC distribution, or
    /// GatewayConfig loading.
    async fn list_spec_owned_plugin_configs(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<crate::config::types::PluginConfig>, anyhow::Error>;

    /// List upstreams owned by a specific api spec (tagged with
    /// `api_spec_id = spec_id`).
    ///
    /// Used by the PUT handler to resolve the existing spec-owned upstream
    /// independently from the mutable proxy.upstream_id pointer, which regular
    /// admin CRUD can change.
    ///
    /// Admin-only. NEVER call from polling loops, gRPC distribution, or
    /// GatewayConfig loading.
    async fn list_spec_owned_upstreams(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<crate::config::types::Upstream>, anyhow::Error>;

    // -----------------------------------------------------------------------
    // Admin audit log (admin-only — runtime config loading and proxy hot paths
    // must never read this table/collection).
    // -----------------------------------------------------------------------

    async fn insert_audit_event(
        &self,
        event: &crate::admin::audit::AuditEvent,
    ) -> Result<(), anyhow::Error>;

    async fn list_audit_events(
        &self,
        namespace: &str,
        filter: &crate::admin::audit::AuditListFilter,
    ) -> Result<PaginatedResult<crate::admin::audit::AuditEvent>, anyhow::Error>;
}

/// Extract resource IDs from a full config.
///
/// This is a pure function on `GatewayConfig`, independent of any backend.
// Used by external test crates; the binary target otherwise flags it as dead code.
#[allow(dead_code)]
pub fn extract_known_ids(
    config: &GatewayConfig,
) -> (
    HashSet<String>,
    HashSet<String>,
    HashSet<String>,
    HashSet<String>,
) {
    let proxy_ids: HashSet<String> = config.proxies.iter().map(|p| p.id.clone()).collect();
    let consumer_ids: HashSet<String> = config.consumers.iter().map(|c| c.id.clone()).collect();
    let plugin_config_ids: HashSet<String> = config
        .plugin_configs
        .iter()
        .map(|pc| pc.id.clone())
        .collect();
    let upstream_ids: HashSet<String> = config.upstreams.iter().map(|u| u.id.clone()).collect();
    (proxy_ids, consumer_ids, plugin_config_ids, upstream_ids)
}

/// Extract the hostname from a database URL, if it contains one.
///
/// Returns `None` for SQLite URLs (file-based, no network host) or
/// if the host portion is already an IP address literal.
pub fn extract_db_hostname(db_url: &str) -> Option<String> {
    let parsed = match url::Url::parse(db_url) {
        Ok(parsed) => parsed,
        Err(_) => return extract_mongodb_multi_host_hostname(db_url),
    };

    let scheme = parsed.scheme().to_lowercase();
    if scheme.contains("sqlite") {
        return None;
    }

    let host = parsed.host_str()?;

    // MongoDB seed lists without explicit ports (e.g.
    // `mongodb://user:pass@mongo1,mongo2/ferrum`) are accepted by `url` as a
    // single comma-joined host. Re-route through the multi-host extractor so
    // DNS rotation tracks the first seed host instead of an unresolvable
    // combined authority.
    if host.contains(',') {
        return extract_mongodb_multi_host_hostname(db_url);
    }

    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }

    Some(host.to_string())
}

/// Redact credentials from a database URL for safe logging.
pub fn redact_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            if parsed.password().is_some() && parsed.set_password(Some("***")).is_err() {
                return "<invalid-url>".to_string();
            }
            if !parsed.username().is_empty() && parsed.set_username("***").is_err() {
                return "<invalid-url>".to_string();
            }
            if let Some(query) = parsed.query() {
                // Redact via the shared option-aware scrubber rather than
                // `query_pairs()`, which only splits on `&` and would leak
                // credentials carried in MongoDB `;`-separated options or in
                // `authMechanismProperties` token lists.
                let redacted_query = redact_query_string(query);
                parsed.set_query(Some(&redacted_query));
            }
            parsed.to_string()
        }
        Err(_) => redact_mongodb_multi_host_url(url).unwrap_or_else(|| "<invalid-url>".to_string()),
    }
}

/// Redact configured database URLs if a driver error includes them verbatim.
pub fn redact_error_text(error: impl std::fmt::Display, urls: &[&str]) -> String {
    let mut text = error.to_string();
    for url in urls {
        text = text.replace(url, &redact_url(url));
    }
    text
}

fn extract_mongodb_multi_host_hostname(db_url: &str) -> Option<String> {
    let authority = mongodb_multi_host_authority(db_url)?;
    let hosts = strip_mongodb_userinfo(authority);
    let first_host = hosts.split(',').next()?.trim();
    if first_host.is_empty() {
        return None;
    }

    let host = if let Some(rest) = first_host.strip_prefix('[') {
        rest.split(']').next()?
    } else {
        first_host.split(':').next().unwrap_or(first_host)
    };
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }

    Some(host.to_string())
}

fn redact_mongodb_multi_host_url(raw_url: &str) -> Option<String> {
    let scheme_len = mongodb_multi_host_scheme_len(raw_url)?;
    let rest = &raw_url[scheme_len..];
    let authority_end = rest
        .find(|ch| ['/', '?', '#'].contains(&ch))
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if !authority.contains(',') {
        return None;
    }

    let redacted_authority = if let Some(at) = authority.rfind('@') {
        format!("***@{}", &authority[at + 1..])
    } else {
        authority.to_string()
    };
    let suffix = redact_url_suffix_query(&rest[authority_end..]);
    Some(format!(
        "{}{}{}",
        &raw_url[..scheme_len],
        redacted_authority,
        suffix
    ))
}

fn mongodb_multi_host_authority(db_url: &str) -> Option<&str> {
    let scheme_len = mongodb_multi_host_scheme_len(db_url)?;
    let rest = &db_url[scheme_len..];
    let authority_end = rest
        .find(|ch| ['/', '?', '#'].contains(&ch))
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    authority.contains(',').then_some(authority)
}

fn mongodb_multi_host_scheme_len(db_url: &str) -> Option<usize> {
    const MONGODB_SCHEME: &str = "mongodb://";
    db_url
        .get(..MONGODB_SCHEME.len())
        .filter(|scheme| scheme.eq_ignore_ascii_case(MONGODB_SCHEME))
        .map(str::len)
}

fn strip_mongodb_userinfo(authority: &str) -> &str {
    authority
        .rfind('@')
        .map(|at| &authority[at + 1..])
        .unwrap_or(authority)
}

fn redact_url_suffix_query(suffix: &str) -> String {
    let Some(query_start) = suffix.find('?') else {
        return suffix.to_string();
    };
    let (before_query, query_and_fragment) = suffix.split_at(query_start + 1);
    let (query, fragment) = match query_and_fragment.find('#') {
        Some(fragment_start) => query_and_fragment.split_at(fragment_start),
        None => (query_and_fragment, ""),
    };
    let redacted_query = redact_query_string(query);
    format!("{before_query}{redacted_query}{fragment}")
}

/// Redact credential-bearing values from a URL query string.
///
/// Splits on both `&` and `;`. MongoDB documents `;` as an accepted option
/// separator, and `url`'s `form_urlencoded` parser only splits on `&`, so a
/// `;`-joined option such as `replicaSet=rs0;password=secret` would otherwise be
/// treated as a single non-sensitive `replicaSet` value and leak the password.
/// Re-serialization normalizes the separator to `&`, which every driver accepts.
fn redact_query_string(query: &str) -> String {
    query
        .split(['&', ';'])
        .filter(|option| !option.is_empty())
        .map(redact_query_option)
        .collect::<Vec<_>>()
        .join("&")
}

/// Redact a single `name[=value]` query option according to its key.
fn redact_query_option(option: &str) -> String {
    let (key, value) = match option.split_once('=') {
        Some((key, value)) => (key, Some(value)),
        None => (option, None),
    };

    let Some(value) = value else {
        return key.to_string();
    };

    let decoded_key = percent_decode_str(key).decode_utf8_lossy();
    let decoded_key = decoded_key.as_ref();

    if is_sensitive_url_query_key(decoded_key) {
        return format!("{key}=***");
    }

    // MongoDB's `authMechanismProperties` carries a comma-separated list of
    // `NAME:VALUE` properties; with MONGODB-AWS the AWS session token rides in
    // `AWS_SESSION_TOKEN:<secret>`. The key itself is not sensitive, so redact
    // any credential-bearing property value within it while keeping benign
    // properties (e.g. `CANONICALIZE_HOST_NAME:true`) for observability. Query
    // parameter names must be matched after percent-decoding so encoded aliases
    // such as `authMechanismPropert%69es` cannot bypass nested redaction.
    if normalize_query_key(decoded_key) == "authmechanismproperties" {
        return format!("{key}={}", redact_mechanism_properties(value));
    }

    format!("{key}={value}")
}

/// Redact credential-bearing properties inside a MongoDB
/// `authMechanismProperties` value (`NAME:VALUE` pairs separated by `,`).
fn redact_mechanism_properties(value: &str) -> String {
    value
        .split(',')
        .map(|property| match property.split_once(':') {
            Some((name, _)) if is_sensitive_url_query_key(name) => format!("{name}:***"),
            _ => property.to_string(),
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn is_sensitive_url_query_key(key: &str) -> bool {
    // Callers pass percent-decoded key names so encoded sensitive aliases such
    // as `pass%77ord` are matched using their semantic query-parameter name.
    // Exact (separator-insensitive) matches for credential-bearing keys that do
    // not contain one of the `SENSITIVE_SUBSTRINGS` below. Compared against the
    // normalized key, so `api_key`, `api-key`, and `apiKey` all match `apikey`.
    const SENSITIVE_KEYS: &[&str] = &[
        "apikey",
        "key",
        "pass",
        "privatekey",
        "sslkey",
        "user",
        "username",
    ];

    // Driver query parameters frequently embed credentials under
    // option-specific aliases (e.g. MongoDB's `tlsCertificateKeyFilePassword`,
    // PostgreSQL's `sslpassword`, OAuth-style `client_secret`/`access_token`).
    // Matching these credential-bearing substrings after normalization keeps
    // such aliases redacted even when they are not in the exact-key list. Only
    // unambiguously secret substrings are listed; path or identifier options
    // like `tlsCertificateKeyFile` (a file path) must not be matched here, so
    // `key`/`user` are intentionally excluded from the substring set.
    const SENSITIVE_SUBSTRINGS: &[&str] = &["password", "passwd", "secret", "token", "credential"];

    let normalized = normalize_query_key(key);
    SENSITIVE_KEYS
        .iter()
        .any(|sensitive| normalized == *sensitive)
        || SENSITIVE_SUBSTRINGS
            .iter()
            .any(|sensitive| normalized.contains(sensitive))
}

/// Normalize a query-parameter key for sensitivity matching: lowercase and
/// strip `-`/`_`/`.` separators so aliases like `client-secret`, `client_secret`,
/// and `clientSecret` all compare equal.
fn normalize_query_key(key: &str) -> String {
    key.chars()
        .filter(|ch| !matches!(ch, '-' | '_' | '.'))
        .flat_map(char::to_lowercase)
        .collect()
}
