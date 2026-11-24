//! Typed, generation-bound mesh identity and metric-label facts (issue #6793).
//!
//! `workload_metrics` attributes every HTTP-family request to a source and a
//! destination workload through thirteen `mesh.source.*` /
//! `mesh.destination.*` label keys. Most of those values are fixed per
//! workload (the local side) or per connection (the verified peer), so this
//! module carries them as immutable `Arc<str>` facts:
//!
//! - [`LocalWorkloadFacts`] is built once per `workload_metrics` instance, so
//!   once per config/identity generation, and is replaced when a reload
//!   rebuilds the instance.
//! - [`RemoteSourceFacts`] describes a verified peer as the source of a
//!   request. A TLS peer's facts are built once per connection
//!   (`SpiffeIdentityConnectionCache::remote_source_facts`); an honored HBONE
//!   assertion or an attested NodeWaypoint pod builds its own per request.
//! - [`MeshLabelShadow`] is the per-request typed copy of the label
//!   projection: exactly the value each label key would hold in
//!   `ctx.metadata` after every `workload_metrics` stamp and gateway mesh
//!   dispatch overlay so far. Writing a slot clones an `Arc`; a repeat stamp
//!   with the same value touches nothing.
//!
//! The string projection in `ctx.metadata` stays the compatibility surface.
//! It is written eagerly, exactly as before, whenever any plugin in the
//! request's chain may observe it ([`crate::plugins::Plugin::observes_mesh_label_metadata`]);
//! only an audited built-in chain defers it, and then nothing can read it. Metric
//! emission builds its key from the shadow, and on an eager request only after
//! proving the summary metadata still holds the shadow's values, so a plugin
//! that rewrote a label is reported exactly as the string parser would.

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::sync::{Arc, LazyLock};

use crate::identity::SpiffeId;

/// Label value the metric parser substitutes for an absent principal,
/// namespace or source workload, and the remote source workload stamped for a
/// peer without a service account.
pub(crate) const UNKNOWN_LABEL: &str = "unknown";

/// Shared `unknown` label, so defaulted keys never allocate.
pub(crate) fn unknown_label() -> &'static Arc<str> {
    static UNKNOWN: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from(UNKNOWN_LABEL));
    &UNKNOWN
}

/// One `mesh.source.*` / `mesh.destination.*` label key that
/// `workload_metrics` (or the gateway's mesh dispatch overlay) stamps for an
/// HTTP-family request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshLabel {
    SourcePrincipal,
    SourceTrustDomain,
    SourceNamespace,
    SourceServiceAccount,
    SourceWorkload,
    SourceApp,
    SourceService,
    DestinationPrincipal,
    DestinationTrustDomain,
    DestinationNamespace,
    DestinationWorkload,
    DestinationApp,
    DestinationService,
}

const MESH_LABEL_COUNT: usize = 13;

impl MeshLabel {
    pub const ALL: [MeshLabel; MESH_LABEL_COUNT] = [
        Self::SourcePrincipal,
        Self::SourceTrustDomain,
        Self::SourceNamespace,
        Self::SourceServiceAccount,
        Self::SourceWorkload,
        Self::SourceApp,
        Self::SourceService,
        Self::DestinationPrincipal,
        Self::DestinationTrustDomain,
        Self::DestinationNamespace,
        Self::DestinationWorkload,
        Self::DestinationApp,
        Self::DestinationService,
    ];

    /// The labels the RED/service-graph key parser reads: everything except
    /// the trust-domain and service-account labels.
    pub const METRIC_KEY_LABELS: [MeshLabel; 10] = [
        Self::SourcePrincipal,
        Self::SourceNamespace,
        Self::SourceWorkload,
        Self::SourceApp,
        Self::SourceService,
        Self::DestinationPrincipal,
        Self::DestinationNamespace,
        Self::DestinationWorkload,
        Self::DestinationApp,
        Self::DestinationService,
    ];

    /// The metadata key this label projects to.
    pub const fn key(self) -> &'static str {
        match self {
            Self::SourcePrincipal => "mesh.source.principal",
            Self::SourceTrustDomain => "mesh.source.trust_domain",
            Self::SourceNamespace => "mesh.source.namespace",
            Self::SourceServiceAccount => "mesh.source.service_account",
            Self::SourceWorkload => "mesh.source.workload",
            Self::SourceApp => "mesh.source.app",
            Self::SourceService => "mesh.source.service",
            Self::DestinationPrincipal => "mesh.destination.principal",
            Self::DestinationTrustDomain => "mesh.destination.trust_domain",
            Self::DestinationNamespace => "mesh.destination.namespace",
            Self::DestinationWorkload => "mesh.destination.workload",
            Self::DestinationApp => "mesh.destination.app",
            Self::DestinationService => "mesh.destination.service",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// The SPIFFE-derived labels of one identity: principal and trust domain,
/// plus namespace and service account when its path carries them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeLabels {
    principal: Arc<str>,
    trust_domain: Arc<str>,
    namespace: Option<Arc<str>>,
    service_account: Option<Arc<str>>,
}

impl SpiffeLabels {
    pub fn new(identity: &SpiffeId) -> Self {
        Self {
            principal: Arc::from(identity.as_str()),
            trust_domain: Arc::from(identity.trust_domain().as_str()),
            namespace: identity.namespace().map(Arc::from),
            service_account: identity.service_account().map(Arc::from),
        }
    }

    pub fn principal(&self) -> &Arc<str> {
        &self.principal
    }

    pub fn trust_domain(&self) -> &Arc<str> {
        &self.trust_domain
    }

    pub fn namespace(&self) -> Option<&Arc<str>> {
        self.namespace.as_ref()
    }

    pub fn service_account(&self) -> Option<&Arc<str>> {
        self.service_account.as_ref()
    }
}

/// This workload's own labels, resolved once per `workload_metrics`
/// instance from its configured identity, namespace and pod labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalWorkloadFacts {
    spiffe: Option<SpiffeLabels>,
    /// The configured namespace, which takes precedence over the SPIFFE
    /// namespace for the local workload's namespace label.
    namespace: Option<Arc<str>>,
    workload: Arc<str>,
    app: Arc<str>,
    service: Arc<str>,
}

impl LocalWorkloadFacts {
    pub fn new(
        spiffe_identity: Option<&SpiffeId>,
        namespace: Option<&str>,
        workload: &str,
        app: &str,
        service: &str,
    ) -> Self {
        Self {
            spiffe: spiffe_identity.map(SpiffeLabels::new),
            namespace: namespace.map(Arc::from),
            workload: Arc::from(workload),
            app: Arc::from(app),
            service: Arc::from(service),
        }
    }

    pub fn spiffe(&self) -> Option<&SpiffeLabels> {
        self.spiffe.as_ref()
    }

    pub fn namespace(&self) -> Option<&Arc<str>> {
        self.namespace.as_ref()
    }

    pub fn workload(&self) -> &Arc<str> {
        &self.workload
    }

    pub fn app(&self) -> &Arc<str> {
        &self.app
    }

    pub fn service(&self) -> &Arc<str> {
        &self.service
    }
}

/// A remote workload attributed as the SOURCE of a request from its SPIFFE
/// ID alone: the inbound peer (or an honored HBONE assertion), or a
/// NodeWaypoint's attested capture source. Its workload, app and service
/// labels are all its service account, or `unknown` without one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSourceFacts {
    spiffe: Option<SpiffeLabels>,
    workload: Arc<str>,
}

impl RemoteSourceFacts {
    pub fn new(identity: Option<&SpiffeId>) -> Self {
        let spiffe = identity.map(SpiffeLabels::new);
        let workload = spiffe
            .as_ref()
            .and_then(|labels| labels.service_account.clone())
            .unwrap_or_else(|| Arc::clone(unknown_label()));
        Self { spiffe, workload }
    }

    /// Facts for a request with no source identity.
    pub fn absent() -> &'static Arc<RemoteSourceFacts> {
        static ABSENT: LazyLock<Arc<RemoteSourceFacts>> =
            LazyLock::new(|| Arc::new(RemoteSourceFacts::new(None)));
        &ABSENT
    }

    pub fn spiffe(&self) -> Option<&SpiffeLabels> {
        self.spiffe.as_ref()
    }

    pub fn workload(&self) -> &Arc<str> {
        &self.workload
    }
}

/// Per-request typed copy of the `mesh.source.*` / `mesh.destination.*`
/// label projection (issue #6793).
///
/// Each slot holds exactly the value its metadata key would hold after the
/// stamps and overlays applied so far, or `None` where the key would be
/// absent. It is crate-private request state: no plugin can author it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeshLabelShadow {
    slots: [Option<Arc<str>>; MESH_LABEL_COUNT],
}

impl MeshLabelShadow {
    pub fn get(&self, label: MeshLabel) -> Option<&str> {
        self.slots[label.index()].as_deref()
    }

    pub(crate) fn get_arc(&self, label: MeshLabel) -> Option<&Arc<str>> {
        self.slots[label.index()].as_ref()
    }

    /// Set `label` to a shared value. An equal value already in the slot is
    /// kept, so a repeat stamp moves no reference counts.
    pub(crate) fn set_arc(&mut self, label: MeshLabel, value: &Arc<str>) {
        let slot = &mut self.slots[label.index()];
        if slot.as_deref() != Some(&**value) {
            *slot = Some(Arc::clone(value));
        }
    }

    /// Set `label` to a borrowed value, allocating only when it changed.
    pub(crate) fn set_str(&mut self, label: MeshLabel, value: &str) {
        let slot = &mut self.slots[label.index()];
        if slot.as_deref() != Some(value) {
            *slot = Some(Arc::from(value));
        }
    }

    pub(crate) fn remove(&mut self, label: MeshLabel) {
        self.slots[label.index()] = None;
    }

    /// Whether the SPIFFE-derived source labels are exactly `labels`'
    /// projection (all absent for `None`).
    pub(crate) fn source_spiffe_matches(&self, labels: Option<&SpiffeLabels>) -> bool {
        match labels {
            None => {
                self.get(MeshLabel::SourcePrincipal).is_none()
                    && self.get(MeshLabel::SourceTrustDomain).is_none()
                    && self.get(MeshLabel::SourceNamespace).is_none()
                    && self.get(MeshLabel::SourceServiceAccount).is_none()
            }
            Some(labels) => {
                self.get(MeshLabel::SourcePrincipal) == Some(&*labels.principal)
                    && self.get(MeshLabel::SourceTrustDomain) == Some(&*labels.trust_domain)
                    && self.get(MeshLabel::SourceNamespace) == labels.namespace.as_deref()
                    && self.get(MeshLabel::SourceServiceAccount)
                        == labels.service_account.as_deref()
            }
        }
    }

    /// Every present label as its `(metadata key, value)` pair, in
    /// [`MeshLabel::ALL`] order.
    pub fn projection(&self) -> impl Iterator<Item = (&'static str, &str)> + '_ {
        MeshLabel::ALL
            .into_iter()
            .filter_map(|label| self.get(label).map(|value| (label.key(), value)))
    }

    /// Whether `metadata` holds exactly this shadow's value (or absence) for
    /// every label the metric key parser reads.
    pub fn metric_key_labels_match<MS: BuildHasher>(
        &self,
        metadata: &HashMap<String, String, MS>,
    ) -> bool {
        MeshLabel::METRIC_KEY_LABELS
            .into_iter()
            .all(|label| metadata.get(label.key()).map(String::as_str) == self.get(label))
    }
}

/// Apply the gateway's outbound mesh-dispatch destination overlay to a
/// request's label shadow: the selected target's `mesh.spiffe_id`,
/// `mesh.namespace`, `mesh.service` and `mesh.trust_domain` tags replace the
/// matching destination labels, exactly as they replace the metadata keys.
pub(crate) fn apply_gateway_destination_overlay<MS: BuildHasher>(
    shadow: &mut MeshLabelShadow,
    tags: &HashMap<String, String, MS>,
) {
    for (tag, label) in [
        ("mesh.spiffe_id", MeshLabel::DestinationPrincipal),
        ("mesh.namespace", MeshLabel::DestinationNamespace),
        ("mesh.service", MeshLabel::DestinationService),
        ("mesh.trust_domain", MeshLabel::DestinationTrustDomain),
    ] {
        if let Some(value) = tags.get(tag) {
            shadow.set_str(label, value);
        }
    }
}

/// Shared label value for a `mesh.request_protocol` / `mesh.response_flags` /
/// `mesh.connection_security_policy` string, without an intern-table lookup
/// for the values the gateway itself stamps.
pub(crate) fn static_label(value: &str) -> Option<&'static Arc<str>> {
    static LABELS: LazyLock<[(&'static str, Arc<str>); 12]> = LazyLock::new(|| {
        [
            "http",
            "grpc",
            "grpc-web",
            "hbone",
            "ws",
            "tcp",
            "udp",
            "mutual_tls",
            "none",
            "-",
            "DC",
            "UF",
        ]
        .map(|value| (value, Arc::from(value)))
    });
    LABELS
        .iter()
        .find(|(known, _)| *known == value)
        .map(|(_, label)| label)
}
