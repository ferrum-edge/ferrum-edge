//! Shared namespace projection for `GatewayConfig` snapshots.
//!
//! A gateway serves exactly one namespace (`FERRUM_NAMESPACE`), but several
//! configuration sources can hand it a snapshot describing many: an
//! all-namespace administrative export, a multi-tenant control-plane cache, or
//! an externally provisioned startup backup file. Serving such a snapshot as it
//! arrives would bind another tenant's listeners and load another tenant's
//! consumers, credentials, plugin policy, upstreams, and trust material.
//!
//! [`retain_namespace`] is the single place that decides which `GatewayConfig`
//! fields are namespace-owned. It destructures the struct **exhaustively, with
//! no `..` rest pattern**, so adding a namespace-owned field to
//! [`GatewayConfig`] fails to compile until this filter states what happens to
//! it. Fields that are not namespace-owned are listed and passed through with a
//! one-line reason.
//!
//! The projection runs BEFORE cross-resource validation at every call site.
//! Uniqueness of `listen_path`, proxy/upstream name and consumer identity is
//! `(namespace, value)`-scoped in both the admin API and the SQL indexes, so
//! validating a multi-namespace view would reject snapshots that are perfectly
//! valid for the namespace actually being served — while duplicates *inside*
//! the active namespace must still reject exactly as they do today.

use crate::config::types::{GatewayConfig, K8sMeshOverlay};

/// Caller-selected policy for the two fields whose correct handling depends on
/// what the projection is FOR, rather than on who owns the data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceRetention {
    /// Replace `known_namespaces` with just the active namespace.
    ///
    /// A serving projection sets this: the discovered namespace list is a set
    /// of foreign tenant names, and a gateway must never serve or authorize
    /// anything from it. An export projection keeps the list, which is the
    /// documented `GET /namespaces` contract for sources that have no
    /// `list_namespaces()` of their own.
    pub collapse_known_namespaces: bool,
    /// Drop the mesh model instead of carrying it through.
    ///
    /// A namespace-scoped mesh projection is not expressible in the
    /// configuration layer (it needs the CP's scope/claim machinery in
    /// `CpGrpcServer::filter_mesh_config_to_namespace`), so a serving
    /// projection fails closed and drops the whole model rather than retaining
    /// a multi-namespace one.
    pub drop_mesh: bool,
}

impl NamespaceRetention {
    /// Projection for a snapshot that is about to be SERVED by a gateway
    /// configured for one namespace. Fails closed on everything it cannot
    /// scope precisely.
    pub const SERVING: Self = Self {
        collapse_known_namespaces: true,
        drop_mesh: true,
    };

    /// Projection for a namespace-scoped administrative EXPORT, which is data
    /// at rest for a later restore rather than a snapshot being served.
    pub const EXPORT: Self = Self {
        collapse_known_namespaces: false,
        drop_mesh: false,
    };
}

/// What [`retain_namespace`] removed, for count-only diagnostics.
///
/// Deliberately counts, never names: a diagnostic emitted by a gateway serving
/// `tenant-a` must not disclose that `tenant-b` exists, let alone name its
/// resources.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NamespaceFilterSummary {
    /// How many distinct namespaces the source snapshot described, including
    /// the active one. `1` means the snapshot was already single-namespace.
    pub source_namespace_count: usize,
    /// How many resources belonged to some other namespace and were dropped.
    pub excluded_resources: usize,
}

/// Number of distinct namespaces owning resources in `config`.
///
/// Count only — the caller never receives the names.
pub fn source_namespace_count(config: &GatewayConfig) -> usize {
    let mut namespaces: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for proxy in &config.proxies {
        namespaces.insert(proxy.namespace.as_str());
    }
    for consumer in &config.consumers {
        namespaces.insert(consumer.namespace.as_str());
    }
    for plugin_config in &config.plugin_configs {
        namespaces.insert(plugin_config.namespace.as_str());
    }
    for upstream in &config.upstreams {
        namespaces.insert(upstream.namespace.as_str());
    }
    for record in &config.gateway_trust_bundles {
        namespaces.insert(record.namespace.as_str());
    }
    for source in &config.frontend_tls_certificate_sources {
        namespaces.insert(source.namespace.as_str());
    }
    for (entry_namespace, _) in &config.http_tls_listen_ports {
        namespaces.insert(entry_namespace.as_str());
    }
    namespaces.len()
}

/// Retain only the resources `namespace` owns, dropping every other tenant's.
///
/// The destructure below is exhaustive on purpose (see the module docs): a new
/// namespace-owned `GatewayConfig` field cannot silently escape this filter.
pub fn retain_namespace(
    config: GatewayConfig,
    namespace: &str,
    retention: NamespaceRetention,
) -> (GatewayConfig, NamespaceFilterSummary) {
    let source_namespaces = source_namespace_count(&config);

    let GatewayConfig {
        // Schema version of the snapshot itself, not tenant data.
        version,
        proxies,
        consumers,
        plugin_configs,
        upstreams,
        // When this snapshot was produced; a property of the load, not a tenant.
        loaded_at,
        known_namespaces,
        // The three legacy frontend-TLS singletons and the per-listener source
        // vector are projected together below by
        // `GatewayConfig::filter_frontend_tls_to_namespace`, which needs the
        // reassembled struct to re-derive the fallback certificate.
        frontend_tls_cert_path,
        frontend_tls_key_path,
        frontend_tls_source_namespace,
        frontend_tls_certificate_sources,
        // Unpartitioned trust material carries no owning namespace; it is
        // operator/env-level input and is left exactly as found. Namespace
        // partitioning of trust happens through `gateway_trust_bundles`.
        trust_bundles,
        gateway_trust_bundles,
        // Per-load bookkeeping produced by THIS process while constructing the
        // candidate (issue #4526). It is `#[serde(skip)]`, so a source snapshot
        // never carries one, and the messages describe rows this load rejected
        // rather than tenant-owned resources. Filtering happens before any
        // quarantine runs, so it is empty here and passed through unchanged.
        quarantined_plugin_configs,
        // Same per-load bookkeeping for stripped shared JWT secrets: filled
        // only by the full loaders after filtering, so empty here.
        quarantined_jwt_shared_secrets,
        mesh,
        http_tls_listen_ports,
        // Monotonic revision of the source snapshot; a property of the
        // authority, not of any namespace.
        mesh_revision,
        // Runtime-only NodeWaypoint datapath metadata (`#[serde(skip)]`),
        // derived during mesh materialization by the node agent. It is never
        // operator input, never present on a deserialized snapshot, and is
        // published only for listeners actually bound on the accepted serving
        // generation, so it carries nothing to project here.
        node_waypoint_udp_steer_destinations,
        node_waypoint_udp_destination_routes,
        // Source-layer authority marker (`#[serde(skip)]`): it says whether a
        // Kubernetes translation owns `mesh`, not who owns any resource. It can
        // however carry the pre-overlay mesh layer, so it moves with `mesh`
        // rather than independently of it.
        k8s_mesh_overlay,
    } = config;

    let pre_filter_resources = proxies.len()
        + consumers.len()
        + plugin_configs.len()
        + upstreams.len()
        + gateway_trust_bundles.len()
        + frontend_tls_certificate_sources.len()
        + http_tls_listen_ports.len();

    let proxies: Vec<_> = proxies
        .into_iter()
        .filter(|proxy| proxy.namespace == namespace)
        .collect();
    let consumers: Vec<_> = consumers
        .into_iter()
        .filter(|consumer| consumer.namespace == namespace)
        .collect();
    let plugin_configs: Vec<_> = plugin_configs
        .into_iter()
        .filter(|plugin_config| plugin_config.namespace == namespace)
        .collect();
    let upstreams: Vec<_> = upstreams
        .into_iter()
        .filter(|upstream| upstream.namespace == namespace)
        .collect();
    // Namespace-keyed trust records are tenant material (issue #3727).
    let gateway_trust_bundles: Vec<_> = gateway_trust_bundles
        .into_iter()
        .filter(|record| record.namespace == namespace)
        .collect();
    // The Gateway-listener TLS classification is namespace-qualified and
    // carries other tenants' namespace names and listener-port topology.
    let http_tls_listen_ports: std::collections::BTreeSet<_> = http_tls_listen_ports
        .into_iter()
        .filter(|(entry_namespace, _)| entry_namespace == namespace)
        .collect();

    let known_namespaces = if retention.collapse_known_namespaces {
        vec![namespace.to_string()]
    } else {
        known_namespaces
    };
    // The overlay marker can hold the pre-overlay mesh layer in `base_mesh`, so
    // dropping the composed model without resetting it would leave exactly the
    // multi-namespace material the drop exists to remove.
    let (mesh, k8s_mesh_overlay) = if retention.drop_mesh {
        (None, K8sMeshOverlay::default())
    } else {
        (mesh, k8s_mesh_overlay)
    };

    let mut filtered = GatewayConfig {
        version,
        proxies,
        consumers,
        plugin_configs,
        upstreams,
        loaded_at,
        known_namespaces,
        frontend_tls_cert_path,
        frontend_tls_key_path,
        frontend_tls_source_namespace,
        frontend_tls_certificate_sources,
        trust_bundles,
        gateway_trust_bundles,
        quarantined_plugin_configs,
        quarantined_jwt_shared_secrets,
        mesh,
        http_tls_listen_ports,
        mesh_revision,
        node_waypoint_udp_steer_destinations,
        node_waypoint_udp_destination_routes,
        k8s_mesh_overlay,
    };

    // Ownership is the owning Gateway's namespace, never the Secret's; this
    // also re-derives the single fallback certificate within the retained set.
    filtered.filter_frontend_tls_to_namespace(namespace);

    let post_filter_resources = filtered.proxies.len()
        + filtered.consumers.len()
        + filtered.plugin_configs.len()
        + filtered.upstreams.len()
        + filtered.gateway_trust_bundles.len()
        + filtered.frontend_tls_certificate_sources.len()
        + filtered.http_tls_listen_ports.len();

    let summary = NamespaceFilterSummary {
        source_namespace_count: source_namespaces,
        excluded_resources: pre_filter_resources.saturating_sub(post_filter_resources),
    };
    (filtered, summary)
}
