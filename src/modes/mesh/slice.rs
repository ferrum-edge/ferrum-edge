use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use tracing::{debug, warn};

use crate::config::types::GatewayConfig;
use crate::identity::spiffe::SpiffeId;
use crate::modes::mesh::config::{
    MeshConfig, MeshDestinationRule, MeshPolicy, MeshProxyConfig, MeshRequestAuthentication,
    MeshRuntimeOverlay, MeshService, MeshSidecar, MeshSidecarEgress, MeshTelemetryResource,
    MeshVirtualServiceCorsPolicy, MtlsMode, MultiClusterConfig, OutboundTrafficPolicy,
    PeerAuthentication, PolicyScope, ResolvedIngressListener, ServiceEntry, SidecarHostPattern,
    TrustBundleSet, Workload, WorkloadLabels, is_false, is_zero_usize,
    policy_scope_applies_to_workload, proxy_config_applies_to_workload, scope_applies_to_workload,
    service_entry_applies_to_workload, virtual_service_cors_policy_exported_to_namespace,
    workload_selector_matches,
};
use crate::modes::mesh::dns_proxy::DEFAULT_CLUSTER_DOMAIN;

/// Node/workload selector used by both ADS and native `MeshSubscribe`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshSliceRequest {
    pub node_id: String,
    pub namespace: String,
    pub workload_spiffe_id: Option<String>,
    /// Name of the GAMMA Waypoint this consumer serves. `Some` only when the
    /// DP's `MeshTopology == ServiceWaypoint`; the slice builder narrows
    /// `services` / `service_entries` (and the workloads / mesh policies that
    /// hang off them) to entries bound to this waypoint via
    /// `MeshConfig.waypoint_bindings`. `None` keeps the legacy behavior of
    /// admitting every resource visible to the workload's namespace.
    pub waypoint_name: Option<String>,
    pub labels: BTreeMap<String, String>,
    /// Kubernetes cluster DNS domain used when synthesizing MeshService FQDN
    /// aliases for Istio Sidecar host matching.
    pub cluster_domain: String,
    /// When `true`, the slice builder applies Istio Sidecar egress scope
    /// narrowing to `service_entries`, `services`, and `destination_rules`.
    /// Defaults to `false` so existing deployments see zero behavior change;
    /// callers wire this from `FERRUM_MESH_SIDECAR_ENFORCED` (or set
    /// directly in tests).
    pub enforce_sidecar_egress: bool,
    /// When `true`, compute the Sidecar egress scope and diagnostics but keep
    /// the slice output on the unenforced path. This lets operators validate
    /// denials before flipping enforcement.
    pub sidecar_egress_dry_run: bool,
    /// When `true`, and only when Sidecar egress narrowing is also enabled and
    /// applicable, the slice builder filters `workloads` to identities
    /// referenced by admitted services. Defaults to `false` for a one-release
    /// dry-run window.
    pub enforce_sidecar_identity_narrowing: bool,
    /// Keep the namespace-visible AuthorizationPolicy candidate superset needed
    /// for destination-side Ambient UDP per-pod source scoping. The consumer
    /// re-filters it only after trusted pod evidence is validated.
    pub ambient_udp_source_scoping: bool,
    /// This subscriber is a **NodeWaypoint** whose transparent inbound capture
    /// listener terminates direct plaintext for the enrolled pods on its node
    /// (issue #3287). Those pods can live in namespaces OTHER than the
    /// NodeWaypoint's own, so the capture path needs a dedicated, least-privilege
    /// destination inventory: the workloads whose trusted
    /// `Workload.node_waypoint.spiffe_id` names THIS NodeWaypoint, plus the
    /// PeerAuthentication candidates applicable to them.
    ///
    /// Deliberately SEPARATE from [`Self::ambient_udp_source_scoping`]: that flag
    /// scopes Ambient/ServiceWaypoint UDP **source** evidence, while NodeWaypoint
    /// UDP stays mesh-wide-only by architecture. Overloading one flag for both
    /// would either widen the UDP source superset for NodeWaypoint or leave the
    /// capture destinations unresolvable.
    ///
    /// The inventory NEVER widens the ordinary routing views (`workloads`,
    /// `services`, `mesh_policies`, `peer_authentications`); it rides its own
    /// slice fields consumed solely by the capture resolver.
    pub node_waypoint_capture_scoping: bool,
}

impl Default for MeshSliceRequest {
    fn default() -> Self {
        Self {
            node_id: String::new(),
            namespace: String::new(),
            workload_spiffe_id: None,
            waypoint_name: None,
            labels: BTreeMap::new(),
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            enforce_sidecar_egress: false,
            sidecar_egress_dry_run: false,
            enforce_sidecar_identity_narrowing: false,
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
        }
    }
}

impl MeshSliceRequest {
    pub fn from_native(
        node_id: String,
        namespace: String,
        workload_spiffe_id: String,
        labels: HashMap<String, String>,
    ) -> Self {
        Self {
            node_id,
            namespace,
            workload_spiffe_id: non_empty(workload_spiffe_id),
            waypoint_name: None,
            labels: labels.into_iter().collect(),
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            enforce_sidecar_egress: false,
            sidecar_egress_dry_run: false,
            enforce_sidecar_identity_narrowing: false,
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
        }
    }

    pub fn from_xds_node(node_id: String, namespace: String) -> Self {
        let workload_spiffe_id = if node_id.starts_with("spiffe://") {
            Some(node_id.clone())
        } else {
            None
        };
        Self {
            node_id,
            namespace,
            workload_spiffe_id,
            waypoint_name: None,
            labels: BTreeMap::new(),
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            enforce_sidecar_egress: false,
            sidecar_egress_dry_run: false,
            enforce_sidecar_identity_narrowing: false,
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
        }
    }

    /// Returns `self` with `enforce_sidecar_egress` set to `enforce`. Builder
    /// pattern keeps the existing constructor signatures stable while letting
    /// callers thread the env-driven flag through without breaking call sites
    /// that don't care about Sidecar scoping (xDS, tests, future protocols).
    pub fn with_enforce_sidecar_egress(mut self, enforce: bool) -> Self {
        self.enforce_sidecar_egress = enforce;
        self
    }

    /// Returns `self` bound to a GAMMA Waypoint name. Used by mesh-mode
    /// startup when `topology == ServiceWaypoint`; tests use it directly.
    #[allow(dead_code)]
    pub fn with_waypoint_name(mut self, name: Option<String>) -> Self {
        self.waypoint_name = name.filter(|value| !value.trim().is_empty());
        self
    }

    /// Returns `self` with dry-run sidecar egress diagnostics enabled.
    pub fn with_sidecar_egress_dry_run(mut self, dry_run: bool) -> Self {
        self.sidecar_egress_dry_run = dry_run;
        self
    }

    /// Returns `self` with workload identity narrowing set to `enforce`.
    /// The builder intentionally does not imply egress narrowing; callers pass
    /// both env-driven flags so tests can exercise the guard independently.
    pub fn with_enforce_sidecar_identity_narrowing(mut self, enforce: bool) -> Self {
        self.enforce_sidecar_identity_narrowing = enforce;
        self
    }

    /// Returns `self` with the cluster DNS domain used for MeshService FQDN
    /// aliases during Sidecar egress matching.
    pub fn with_cluster_domain(mut self, cluster_domain: String) -> Self {
        self.cluster_domain = cluster_domain;
        self
    }

    pub fn with_ambient_udp_source_scoping(mut self, enabled: bool) -> Self {
        self.ambient_udp_source_scoping = enabled;
        self
    }

    /// Returns `self` marked as a NodeWaypoint transparent-inbound-capture
    /// subscription (issue #3287). See
    /// [`MeshSliceRequest::node_waypoint_capture_scoping`].
    pub fn with_node_waypoint_capture_scoping(mut self, enabled: bool) -> Self {
        self.node_waypoint_capture_scoping = enabled;
        self
    }

    /// Override the workload SPIFFE id when provided. Used by the xDS CP to
    /// apply the identity carried in `Node.metadata` (which takes precedence
    /// over any `node_id`-derived value); `None` leaves the existing value so a
    /// `spiffe://` node id still resolves via `from_xds_node`.
    pub fn with_workload_spiffe_id(mut self, workload_spiffe_id: Option<String>) -> Self {
        if workload_spiffe_id.is_some() {
            self.workload_spiffe_id = workload_spiffe_id;
        }
        self
    }
}

/// Canonical per-node mesh view. This is the common source for both xDS
/// translators and native ConfigSync mesh subscribers.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MeshSlice {
    pub node_id: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_spiffe_id: Option<String>,
    /// GAMMA Waypoint identity for this slice. `Some` only when the DP
    /// requested a service-scoped waypoint slice; informational on the wire
    /// so consumers can identify the binding the projection narrowed to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waypoint_name: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// `labels` is an AMBIGUOUS intersection inferred from a shared-SPIFFE match
    /// across multiple workloads, NOT this workload's authoritative label set.
    /// Set only when the slice request carried no explicit labels and more than
    /// one workload shared the SPIFFE id, so `labels` is the (possibly empty)
    /// intersection while `mesh_policies` / `peer_authentications` /
    /// `request_authentications` carry the candidate-any superset.
    ///
    /// Consumers that hold the workload's real labels MUST prefer those over the
    /// intersection when this is `true`: the xDS DP re-filters the superset
    /// against its local `FERRUM_MESH_WORKLOAD_LABELS` rather than letting the
    /// non-empty intersection carrier replace them (otherwise a candidate-only
    /// selector PeerAuthentication / RequestAuthentication / AuthorizationPolicy
    /// is silently dropped — a fail-open whenever the intersection is non-empty).
    /// `false` (the default) means `labels` is authoritative; never serialized
    /// when unset so non-ambiguous slices stay byte-identical on the wire.
    #[serde(default, skip_serializing_if = "is_false")]
    pub labels_ambiguous: bool,
    pub version: String,
    /// Authoritative, CP-replica-shared config revision this slice was built
    /// from (issue #2473).
    ///
    /// `version` is the CP's local `GatewayConfig.loaded_at` rendering and is
    /// observability-only: it is a wall clock, so it is not comparable across
    /// CP replicas, clock skew, or restarts. `revision` is the ordering field —
    /// see [`crate::modes::mesh::revision`] for the comparison contract the DP
    /// freshness gate enforces before any `ArcSwap` replacement.
    ///
    /// `None` when the CP's config authority has no shared monotonic sequence
    /// (K8s CRD controller, file source). Deliberately EXCLUDED from
    /// [`MeshSlice::content_eq`]: like `version`, it is ordering metadata, not
    /// content, and CP-side dedupe must keep suppressing frames whose resources
    /// did not change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<crate::modes::mesh::revision::MeshConfigRevision>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workloads: Vec<Workload>,
    /// Workloads eligible to bind trusted Ambient UDP `source.pod_uid`
    /// evidence. Kept separate from `workloads` because ServiceWaypoint narrows
    /// that field to destination backends, while a source pod normally is not a
    /// backend of the service whose waypoint terminates its HBONE datagram.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ambient_udp_source_workloads: Vec<Workload>,
    /// Exact NodeWaypoint SPIFFE IDs trusted to assert HBONE source workload
    /// identity for this slice. Unlike `workloads`, this inventory is derived
    /// from scope-authorized `Workload.node_waypoint` endpoints before
    /// namespace or service-scope narrowing so a destination slice can still
    /// trust the source node waypoint for legitimate cross-namespace traffic.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_waypoint_assertors: Vec<SpiffeId>,
    /// Destination workloads this NodeWaypoint's transparent inbound capture
    /// listener may terminate direct plaintext for (issue #3287).
    ///
    /// A NodeWaypoint serves every enrolled pod on its node, and those pods can
    /// live in namespaces OTHER than the NodeWaypoint's own — so `workloads`
    /// (narrowed to the subscription namespace / service-waypoint visibility)
    /// cannot answer "which workload owns this captured original destination".
    /// This inventory is derived from workloads whose trusted
    /// `Workload.node_waypoint.spiffe_id` names THIS NodeWaypoint, with CP scope
    /// and bearer-namespace constraints applied before it crosses the boundary.
    ///
    /// It is a CAPTURE-ONLY view: it never widens `workloads` / `services` /
    /// routing visibility, and is read solely by
    /// `crate::proxy::resolve_node_waypoint_capture_destination`. Empty means
    /// the capture path resolves NOTHING and fails closed — never a PERMISSIVE
    /// default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_waypoint_capture_destinations: Vec<Workload>,
    /// PeerAuthentication candidates applicable to
    /// [`Self::node_waypoint_capture_destinations`] (issue #3287).
    ///
    /// `peer_authentications` is narrowed to the subscription namespace, so a
    /// STRICT PeerAuthentication in a CAPTURED pod's own namespace would never
    /// reach a NodeWaypoint deployed elsewhere — and the capture resolver would
    /// see no policy and default PERMISSIVE, admitting direct plaintext where
    /// STRICT is required. This carries exactly the candidates the destination
    /// resolution needs (mesh-wide/root-namespace, namespace-scoped, and
    /// selector-scoped entries applicable to the destination workloads), and
    /// nothing else. Istio precedence and port overrides are then resolved by
    /// the canonical [`resolve_effective_mtls_mode`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_waypoint_capture_peer_authentications: Vec<PeerAuthentication>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<MeshService>,
    /// Inbound-only view: the LOCAL workload's own service(s), captured
    /// **un-narrowed** by Sidecar egress scope. `services` is the egress/
    /// outbound view (narrowed, and feeds `build_known_destinations`); egress
    /// scope must not gate *inbound* serving, so sidecar inbound route
    /// materialization reads this separate view instead. Populated only when
    /// Sidecar egress narrowing is active and a local workload identity is
    /// known; empty otherwise (then `services` is the full set and the
    /// materializer falls back to it). Kept out of `services` so the outbound
    /// registry / egress scope is never widened by it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_inbound_services: Vec<MeshService>,
    /// The local workload(s) backing this sidecar, captured **un-narrowed** by
    /// Sidecar egress/identity narrowing. `workloads` is narrowed under
    /// `FERRUM_MESH_SIDECAR_IDENTITY_NARROWING` (it drops workloads that don't
    /// back an egress-admitted service — including the local pod when its own
    /// service isn't admitted), which would leave the inbound materializer
    /// unable to find the local workload. This separate view preserves it (and
    /// its container ports for backend resolution) without widening the narrowed
    /// `workloads`/known-destinations view.
    ///
    /// `Some` is the AUTHORITATIVE resolved local-inbound view (it gates whether
    /// `local_inbound_services` is consulted); `Some(empty)` means the local
    /// identity was resolved but **ambiguous** (a shared service-account SPIFFE
    /// with no labels) and must materialize NO routes — the materializer must
    /// NOT fall back to the narrowed `workloads`, which could collapse the
    /// ambiguity to one (wrong) service. `None` means no narrowing applied, so
    /// the materializer falls back to the full `workloads`/`services`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_inbound_workloads: Option<Vec<Workload>>,
    /// Resolved custom inbound listeners from the local workload's applicable
    /// Istio `Sidecar.ingress[]`. Computed at slice build (the applicable
    /// Sidecar is resolved CP-side; raw `MeshSidecar` records do not ride the
    /// slice, only this resolved view — mirroring `local_inbound_services`).
    /// Per Istio semantics, when this is non-empty it **replaces** the default
    /// per-service-port inbound materialization for the workload: the inbound
    /// materializer emits one loopback route per entry (listener port → the
    /// entry's `defaultEndpoint`) instead of the service-port defaults. Only
    /// resolvable entries land here; unsupported shapes (Unix-socket /
    /// non-loopback `defaultEndpoint`, non-HTTP-family protocol) are dropped at
    /// resolution and reported as deferred. Empty when no Sidecar applies, the
    /// Sidecar declares no ingress, or no entry resolved.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_ingress_listeners: Vec<ResolvedIngressListener>,
    /// Fail-closed marker: the local workload's applicable `Sidecar` declared a
    /// NON-EMPTY `spec.ingress[]`, independent of whether any entry RESOLVED
    /// into `local_ingress_listeners`. Per Istio, declaring `ingress[]` REPLACES
    /// the default per-service-port inbound listeners; so when this is `true`
    /// the inbound materializer SKIPS the default routes even if
    /// `local_ingress_listeners` is empty (every entry unsupported, or no local
    /// service anchored them) — exposing the default `:15006` loopback routes
    /// for a workload whose operator declared (failed-closed) custom ingress
    /// would be a fail-open regression. `local_ingress_listeners` non-empty
    /// implies this is `true`; this can be `true` with an empty listener list.
    #[serde(default, skip_serializing_if = "is_false")]
    pub sidecar_ingress_declared: bool,
    /// Count of DISTINCT HTTP-family `ingress[]` listener ports the local
    /// workload's applicable Sidecar DECLARED (F6 §6.2), independent of how many
    /// resolved into `local_ingress_listeners`. It can EXCEED the resolved count
    /// when an HTTP-family entry's `defaultEndpoint` is omitted / `unix://` /
    /// off-box (the entry still declared a distinct listener port). The router
    /// uses it as the ingress group's `declared_http_ports` so a partially
    /// materialized group stays AMBIGUOUS to an orig-dst-less request — without
    /// it, two declared listeners with one resolved collapse to the single-listener
    /// no-signal pass-through and the surviving sibling wrongly absorbs the skipped
    /// port's traffic. `0` when no ingress was declared, none was HTTP-family, or
    /// the listeners were dropped for lack of a local-service anchor.
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub declared_ingress_http_ports: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mesh_policies: Vec<MeshPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_authentications: Vec<PeerAuthentication>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_entries: Vec<ServiceEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_authentications: Vec<MeshRequestAuthentication>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub telemetry_resources: Vec<MeshTelemetryResource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination_rules: Vec<MeshDestinationRule>,
    /// VirtualService-derived host-level CORS policies (issue #1973),
    /// narrowed like `destination_rules`. The DP synthesizes per-route `cors`
    /// plugin instances onto materialized outbound routes from these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub virtual_service_cors_policies: Vec<MeshVirtualServiceCorsPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_configs: Vec<MeshProxyConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_bundles: Option<TrustBundleSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi_cluster: Option<MultiClusterConfig>,
    /// Effective outbound traffic policy for this workload slice. `None`
    /// keeps the legacy `AllowAny` behavior (runtime env fallback). When
    /// `Some(RegistryOnly)`, the slice-apply path auto-injects the
    /// `mesh_outbound_registry` plugin with a registry built from
    /// `services` ∪ `service_entries` ∪ `workloads.addresses`, and stream-
    /// family capture paths consult the same registry.
    ///
    /// Resolved CP-side as: applicable [`MeshSidecar::outbound_traffic_policy`]
    /// (same Sidecar selection tiers as egress/ingress) when set, else
    /// [`MeshConfig::outbound_traffic_policy`]. The Sidecar records themselves
    /// do not ride the slice; only this effective value is carried (native /
    /// xDS `OutboundTrafficPolicyCarrier`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_traffic_policy: Option<OutboundTrafficPolicy>,
    /// Cold-path operator view of the Sidecar egress scope that was applied,
    /// or would have been applied when dry-run is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidecar_egress_scope: Option<MeshEgressScopeSnapshot>,
    /// Operator-defined ECDS (Extension Config Discovery Service) entries.
    /// These flow through xDS as
    /// `type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig`
    /// resources. The xDS server emits them verbatim so a CP can hand
    /// arbitrary typed extension configs to subscribed DPs.
    ///
    /// GAP-2K's DR-carrier path uses this surface to ship the original
    /// DestinationRule JSON across xDS when full DR semantics are needed:
    /// the CP wraps the DR JSON in a `MeshExtensionConfig` with a
    /// Ferrum-specific `type_url`, and the DP xDS consumer recognizes the
    /// `type_url` and applies the DR locally instead of relying on the
    /// fragmentary CDS/EDS recoverable fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extension_configs: Vec<MeshExtensionConfig>,
    /// xDS RTDS (`envoy.service.runtime.v3.Runtime`) overlay merged across
    /// all subscribed layers. Fault-injection values are captured in the
    /// accepted request epoch's plugin cache; transformer gates and tracing
    /// level are published by `runtime_overlay_consumers::apply_overlay`.
    /// Received-but-rejected slices stay visible only on the raw runtime
    /// snapshot and never reach either live surface.
    #[serde(default, skip_serializing_if = "MeshRuntimeOverlay::is_empty")]
    pub runtime_overlay: MeshRuntimeOverlay,
}

/// One opaque typed extension config, transported through xDS ECDS.
///
/// `name` and `type_url` identify the extension; `value` is the
/// already-serialized inner typed payload. Do not include the protobuf field
/// tag or length delimiter for `Any.value`; prost adds those when the outer
/// `Any` is encoded. The DP-side consumer is responsible for recognizing
/// `type_url` and deserializing `value` into its own representation; the xDS
/// layer treats everything inside `value` as uninterpreted bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshExtensionConfig {
    pub name: String,
    /// Namespace this extension config is allowed to reach via per-node mesh
    /// slices. Empty means "unscoped" and is intentionally dropped during
    /// slice construction to avoid cross-namespace leakage.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub namespace: String,
    pub type_url: String,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "extension_value_bytes"
    )]
    pub value: Vec<u8>,
}

mod extension_value_bytes {
    use base64::Engine as _;
    use base64::alphabet;
    use base64::engine::DecodePaddingMode;
    use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Encode side stays canonical `STANDARD` (padded). Decode side is lenient
    /// on padding so an upstream CP that strips trailing `=` characters still
    /// round-trips correctly. Alphabet stays `STANDARD` (`+/`) — we never
    /// silently accept the URL-safe alphabet (`-_`) because mixing alphabets
    /// would corrupt non-text payloads on decode.
    const DECODE_LENIENT: GeneralPurpose = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_encode_padding(true)
            .with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        DECODE_LENIENT
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshEgressScopeSnapshot {
    #[serde(default)]
    pub sidecar_enforced: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub sidecar_applied: bool,
    #[serde(default)]
    pub sidecar_admitted_services: usize,
    #[serde(default)]
    pub sidecar_denied_services: usize,
    /// Admitted DestinationRules after Sidecar egress narrowing. Surfaced so
    /// operators can verify which DRs the resolved scope reaches (DRs are one
    /// of the three resources affected by Sidecar narrowing, alongside
    /// services and service_entries).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination_rules: Vec<MeshEgressScopeResource>,
    /// Count of DestinationRules in scope before narrowing was applied,
    /// matched against the workload namespace using the same predicate as the
    /// narrowed pass. `destination_rules.len()` is the admitted count.
    #[serde(default)]
    pub sidecar_admitted_destination_rules: usize,
    #[serde(default)]
    pub sidecar_denied_destination_rules: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<MeshEgressScopeResource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_entries: Vec<MeshEgressScopeResource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_destinations: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshEgressScopeResource {
    pub namespace: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
}

pub(crate) fn node_waypoint_assertors_from_workloads<'a>(
    workloads: impl IntoIterator<Item = &'a Workload>,
) -> Vec<SpiffeId> {
    let mut ids = BTreeMap::new();
    for workload in workloads {
        if let Some(node_waypoint) = workload.node_waypoint.as_ref() {
            ids.entry(node_waypoint.spiffe_id.as_str().to_string())
                .or_insert_with(|| node_waypoint.spiffe_id.clone());
        }
    }
    ids.into_values().collect()
}

/// Destination workloads a NodeWaypoint identified by `node_waypoint_spiffe_id`
/// terminates transparent inbound capture for (issue #3287).
///
/// A workload is admitted only when its trusted `Workload.node_waypoint`
/// endpoint names EXACTLY this NodeWaypoint's SPIFFE ID — the same field the
/// secured NodeWaypoint transport pins as the destination's server identity.
/// This is intentionally the narrowest available key: it is per-node, it is set
/// by the config authority (never by the pod), and it does not depend on
/// namespace visibility, so a legitimately cross-namespace enrolled pod is
/// carried while every unrelated workload is excluded.
///
/// Fails closed on a missing/blank identity: without knowing WHICH NodeWaypoint
/// is asking there is no least-privilege answer, so the inventory is empty and
/// the capture path resolves nothing.
///
/// Callers are responsible for applying CP scope / bearer-namespace constraints
/// to `workloads` BEFORE calling; this function applies no authorization of its
/// own.
pub(crate) fn node_waypoint_capture_destinations_from_workloads<'a>(
    workloads: impl IntoIterator<Item = &'a Workload>,
    node_waypoint_spiffe_id: Option<&str>,
) -> Vec<Workload> {
    let Some(node_waypoint_spiffe_id) = node_waypoint_spiffe_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Vec::new();
    };
    workloads
        .into_iter()
        .filter(|workload| {
            workload
                .node_waypoint
                .as_ref()
                .is_some_and(|endpoint| endpoint.spiffe_id.as_str() == node_waypoint_spiffe_id)
        })
        .cloned()
        .collect()
}

/// PeerAuthentication candidates applicable to `destinations` (issue #3287).
///
/// Uses the canonical `peer_auth_applies_to_workload` predicate against each
/// destination workload's OWN namespace and labels, so Istio's root-namespace /
/// mesh-wide, namespace-scoped, and selector-scoped applicability are all
/// preserved exactly as the destination itself would resolve them. Precedence
/// and port overrides are NOT resolved here — that stays with
/// [`resolve_effective_mtls_mode`] at capture time, against the single exact
/// destination.
///
/// Returns an empty vec for an empty destination set: with no destination there
/// is nothing to authorize and carrying policy would only leak it.
pub(crate) fn node_waypoint_capture_peer_authentications_for_destinations<'a>(
    peer_authentications: impl IntoIterator<Item = &'a PeerAuthentication>,
    destinations: &[Workload],
) -> Vec<PeerAuthentication> {
    if destinations.is_empty() {
        return Vec::new();
    }
    let destination_scopes: Vec<(String, BTreeMap<String, String>)> = destinations
        .iter()
        .map(|workload| {
            (
                workload.namespace.clone(),
                labels_to_btree(&workload.selector.labels),
            )
        })
        .collect();
    peer_authentications
        .into_iter()
        .filter(|peer_auth| {
            destination_scopes.iter().any(|(namespace, labels)| {
                peer_auth_applies_to_workload(peer_auth, namespace, labels)
            })
        })
        .cloned()
        .collect()
}

impl MeshSlice {
    /// Compare mesh-slice content while ignoring the transport version stamp.
    ///
    /// MeshSubscribe uses this to suppress no-op updates. Keep the comparison
    /// beside the struct so future fields are considered when the model grows.
    pub fn content_eq(&self, other: &Self) -> bool {
        self.node_id == other.node_id
            && self.namespace == other.namespace
            && self.workload_spiffe_id == other.workload_spiffe_id
            && self.waypoint_name == other.waypoint_name
            && self.labels == other.labels
            // The ambiguous-labels marker can flip independently of `labels`
            // (e.g. the shared-SPIFFE candidate set shrinks from two workloads
            // to one while the intersection is unchanged), changing how the xDS
            // DP resolves label precedence. It MUST be compared so the slice is
            // re-broadcast and the DP stops deferring to (or starts deferring
            // to) its local labels; omitting it would keep the stale precedence.
            && self.labels_ambiguous == other.labels_ambiguous
            && self.workloads == other.workloads
            && self.ambient_udp_source_workloads == other.ambient_udp_source_workloads
            && self.node_waypoint_assertors == other.node_waypoint_assertors
            // The NodeWaypoint capture inventory changes independently of
            // `workloads` / `peer_authentications` (a pod in ANOTHER namespace
            // enrolling on this node, or that namespace's PeerAuthentication
            // flipping to STRICT, moves only these two fields). Omitting them
            // from slice equality would let CP-side dedupe keep serving a stale
            // capture posture — i.e. admitting plaintext after the operator made
            // the destination STRICT.
            && self.node_waypoint_capture_destinations == other.node_waypoint_capture_destinations
            && self.node_waypoint_capture_peer_authentications
                == other.node_waypoint_capture_peer_authentications
            && self.services == other.services
            && self.local_inbound_services == other.local_inbound_services
            && self.local_inbound_workloads == other.local_inbound_workloads
            && self.local_ingress_listeners == other.local_ingress_listeners
            // The fail-closed `sidecar_ingress_declared` marker flips independently
            // of `local_ingress_listeners` (no `ingress[]` → an all-unsupported
            // `ingress[]` leaves the resolved list empty while the marker goes
            // `false`→`true`). It MUST be compared so MeshSubscribe/update dedupe
            // re-sends the slice and the materializer suppresses the now-stale
            // default inbound routes; omitting it would keep serving them.
            && self.sidecar_ingress_declared == other.sidecar_ingress_declared
            // The declared ingress port count drives the router's fail-closed
            // port ambiguity and flips independently of `local_ingress_listeners`
            // (e.g. adding an HTTP-family entry whose `defaultEndpoint` is
            // unroutable raises the declared count without changing the resolved
            // set). It MUST be compared so a change re-applies the slice and the
            // router stops treating a now-partially-materialized group as a
            // single-listener pass-through.
            && self.declared_ingress_http_ports == other.declared_ingress_http_ports
            && self.mesh_policies == other.mesh_policies
            && self.peer_authentications == other.peer_authentications
            && self.service_entries == other.service_entries
            && self.request_authentications == other.request_authentications
            && self.telemetry_resources == other.telemetry_resources
            && self.destination_rules == other.destination_rules
            && self.virtual_service_cors_policies == other.virtual_service_cors_policies
            && self.proxy_configs == other.proxy_configs
            && self.trust_bundles == other.trust_bundles
            && self.multi_cluster == other.multi_cluster
            && self.outbound_traffic_policy == other.outbound_traffic_policy
            && self.sidecar_egress_scope == other.sidecar_egress_scope
            && self.extension_configs == other.extension_configs
            && self.runtime_overlay == other.runtime_overlay
    }

    /// Build the set of known mesh destinations from this slice. Used by
    /// the auto-injected `mesh_outbound_registry` plugin when
    /// `outbound_traffic_policy == RegistryOnly`. Includes:
    ///   - service `{name}` for services in this slice's namespace,
    ///     `{name}.{namespace}`,
    ///     `{name}.{namespace}.svc`, and
    ///     `{name}.{namespace}.svc.{cluster_domain}` forms with their
    ///     declared ports. Resources without declared ports also get a
    ///     `host:*` marker so REGISTRY_ONLY treats the known destination as
    ///     valid when HTTP callers include an explicit Host port.
    ///   - `service_entries.hosts` with their declared ports
    ///   - `workloads.addresses`
    ///
    /// Returned entries are alphabetically sorted so the plugin config is
    /// deterministic across reloads (preventing spurious slice-update
    /// re-broadcasts via `content_eq`).
    pub fn build_known_destinations(&self, cluster_domain: &str) -> Vec<String> {
        let mut entries: HashSet<String> = HashSet::new();
        let cluster_domain = normalize_known_destination_host(cluster_domain).unwrap_or_default();
        let local_namespace = normalize_known_destination_host(&self.namespace);
        for service in &self.services {
            let Some(service_name) = normalize_known_destination_host(&service.name) else {
                continue;
            };
            let Some(namespace) = normalize_known_destination_host(&service.namespace) else {
                continue;
            };
            let namespaced = format!("{service_name}.{namespace}");
            let svc = format!("{namespaced}.svc");
            let fqdn = if cluster_domain.is_empty() {
                svc.clone()
            } else {
                format!("{svc}.{cluster_domain}")
            };
            if local_namespace.as_deref() == Some(namespace.as_str()) {
                insert_known_destination(
                    &mut entries,
                    &service_name,
                    service.ports.iter().map(|p| p.port),
                );
            }
            for host in [&namespaced, &svc, &fqdn] {
                insert_known_destination(&mut entries, host, service.ports.iter().map(|p| p.port));
            }
        }
        for entry in &self.service_entries {
            for host in &entry.hosts {
                let Some(host) = normalize_known_destination_host(host) else {
                    continue;
                };
                insert_known_destination(&mut entries, &host, entry.ports.iter().map(|p| p.port));
            }
        }
        for workload in &self.workloads {
            for addr in &workload.addresses {
                let Some(addr) = normalize_known_destination_host(addr) else {
                    continue;
                };
                insert_known_destination(
                    &mut entries,
                    &addr,
                    workload.ports.iter().map(|p| p.port),
                );
            }
        }
        let mut sorted: Vec<String> = entries.into_iter().collect();
        sorted.sort();
        sorted
    }

    /// Resolve the effective mTLS mode for a given port on this workload.
    ///
    /// PeerAuthentication scope precedence (highest wins):
    ///   1. WorkloadSelector-scoped (has `selector` with labels matching this workload)
    ///   2. Namespace-scoped (no selector, same namespace)
    ///   3. Mesh-wide (root namespace, no selector — carried via `peer_authentications`
    ///      which is already pre-filtered by `from_gateway_config`)
    ///
    /// Within the winning policy, a port-level override for `port` takes
    /// precedence over the policy's top-level `mtls_mode`.
    ///
    /// When no PeerAuthentication applies, returns `MtlsMode::Permissive`
    /// (Istio default).
    pub fn resolve_effective_mtls_mode(&self, port: u16) -> MtlsMode {
        resolve_effective_mtls_mode(
            &self.peer_authentications,
            &self.namespace,
            &self.labels,
            port,
        )
    }

    /// Resolve the effective inbound mTLS mode for `port`, FAILING CLOSED on an
    /// ambiguous shared-SPIFFE slice whose partial label intersection cannot
    /// confirm a candidate-only selector PeerAuthentication.
    ///
    /// On a `labels_ambiguous` slice, `self.labels` is only the intersection of
    /// the divergent candidates sharing this SPIFFE, NOT this workload's
    /// authoritative labels, and `peer_authentications` carries the candidate-any
    /// superset (a STRICT PeerAuth that matches only ONE candidate rode in). The
    /// plain [`Self::resolve_effective_mtls_mode`] re-filters by the partial
    /// intersection, so such a selector STRICT is silently dropped and the
    /// listener falls back to `Permissive` — a silent fail-OPEN: a workload whose
    /// real labels match the selector would have required mTLS.
    ///
    /// When the marker is set, we cannot prove an unresolvable selector
    /// PeerAuth does NOT apply, so we ESCALATE to the most-restrictive effective
    /// mode any such candidate-only selector PeerAuth would yield for this port
    /// (Strict > Permissive > Disable), but never DOWNGRADE below the
    /// normally-resolved mode. The operator's remedy is to pin
    /// `FERRUM_MESH_WORKLOAD_LABELS` / `mesh_slice.labels` so the marker clears
    /// and the superset is re-filtered deterministically. A non-ambiguous slice
    /// (the marker absent — unique SPIFFE, concrete request labels, or a DP that
    /// resolved its authoritative labels) is enforcement-IDENTICAL to the plain
    /// resolver.
    pub fn resolve_inbound_mtls_mode_fail_closed(&self, port: u16) -> MtlsMode {
        if !self.labels_ambiguous {
            return self.resolve_effective_mtls_mode(port);
        }
        self.resolve_inbound_mtls_mode_fail_closed_with(|pa| peer_auth_effective_mode(pa, port))
    }

    /// Workload-level counterpart to
    /// [`Self::resolve_inbound_mtls_mode_fail_closed`]. This preserves the
    /// ambiguous-label fail-closed escalation while deliberately excluding
    /// every app-port override from the listener-wide fallback.
    pub fn resolve_inbound_workload_mtls_mode_fail_closed(&self) -> MtlsMode {
        self.resolve_inbound_mtls_mode_fail_closed_with(|pa| pa.mtls_mode)
    }

    fn resolve_inbound_mtls_mode_fail_closed_with(
        &self,
        mode_for: impl Fn(&PeerAuthentication) -> MtlsMode + Copy,
    ) -> MtlsMode {
        let resolved = resolve_peer_auth_mtls_mode(
            &self.peer_authentications,
            &self.namespace,
            &self.labels,
            mode_for,
        );
        if !self.labels_ambiguous {
            return resolved;
        }
        // Most-restrictive mode among candidate-any selector PeerAuths that the
        // partial intersection could NOT confirm (the plain resolver dropped
        // them). Only WorkloadSelector-scoped entries with non-empty selector
        // labels are at risk: namespace/mesh-wide scopes resolve against the
        // authoritative `self.namespace`, not the ambiguous labels. A selector
        // whose NAMESPACE does not match `self.namespace` is also authoritatively
        // non-applicable (namespace is not ambiguous), so only LABEL divergence
        // is escalated here.
        let mut effective = resolved;
        for pa in &self.peer_authentications {
            if classify_peer_auth_scope(pa) != PeerAuthScope::WorkloadSelector {
                continue;
            }
            if peer_auth_applies_to_workload(pa, &self.namespace, &self.labels) {
                // Already accounted for by the normal resolution above.
                continue;
            }
            // Skip selectors that fail to apply for a reason OTHER than the
            // ambiguous labels — i.e. a namespace mismatch, which is
            // authoritative. Re-test the selector against the workload labels but
            // with the namespace constraint honored: if it still does not match
            // even when the slice IS this workload (label superset assumption),
            // the mismatch is the namespace, not the labels.
            if !peer_auth_selector_namespace_matches(pa, &self.namespace) {
                continue;
            }
            let candidate = mode_for(pa);
            if peer_auth_mtls_restrictiveness(candidate) < peer_auth_mtls_restrictiveness(effective)
            {
                effective = candidate;
            }
        }
        if effective != resolved {
            tracing::warn!(
                resolved = ?resolved,
                fail_closed = ?effective,
                "mesh PeerAuthentication: ambiguous shared-SPIFFE slice carries a candidate-only \
                 selector PeerAuthentication the partial label intersection cannot resolve; \
                 escalating inbound mTLS to the most-restrictive candidate mode (fail closed). \
                 Set FERRUM_MESH_WORKLOAD_LABELS / mesh_slice.labels to pin this workload's \
                 identity for deterministic resolution"
            );
        }
        effective
    }

    /// Returns the most-specific applicable [`MeshProxyConfig`] for this slice's
    /// workload, or `None` when no `ProxyConfig` applies.
    ///
    /// Specificity ordering mirrors Istio's `PolicyScope` tiers:
    /// `WorkloadSelector` > `Namespace` > `MeshWide`. Among same-tier
    /// matches the ASCII-smallest `name` wins — deterministic tiebreaker
    /// that mirrors the accumulator's `(namespace, name)` sort so consumers
    /// see a stable choice regardless of informer delivery order.
    ///
    /// Slice construction in [`Self::from_gateway_config`] already filters
    /// `proxy_configs` down to those visible to the current node, so this
    /// method just resolves specificity among matched entries.
    pub fn resolved_proxy_config(&self) -> Option<&MeshProxyConfig> {
        self.proxy_configs.iter().min_by(|a, b| {
            // Higher tier first (reverse cmp), then smaller name first.
            // `min_by` picks the comparator's smallest, so:
            //   - WorkloadSelector (2) < Namespace (1) < MeshWide (0) after reverse
            //   - within same tier, the ASCII-smallest name wins
            proxy_config_scope_tier(b)
                .cmp(&proxy_config_scope_tier(a))
                .then_with(|| a.name.as_str().cmp(b.name.as_str()))
        })
    }

    pub fn from_gateway_config(config: &GatewayConfig, request: MeshSliceRequest) -> Self {
        let version = config.loaded_at.to_rfc3339();
        // Ordering metadata rides the snapshot, not the projection: every
        // per-workload slice built from one `GatewayConfig` carries the same
        // authoritative revision, so a DP comparing two CPs' slices compares
        // their config generations rather than their wall clocks.
        let revision = config.mesh_revision.clone();
        let Some(mesh) = config.mesh.as_ref() else {
            return Self {
                node_id: request.node_id,
                namespace: request.namespace,
                workload_spiffe_id: request.workload_spiffe_id,
                waypoint_name: request.waypoint_name,
                labels: request.labels,
                version,
                revision,
                ..Self::default()
            };
        };

        let namespace = request.namespace.clone();
        let cluster_domain = request.cluster_domain.clone();
        let sidecar_enforced = request.enforce_sidecar_egress;
        let sidecar_dry_run = request.sidecar_egress_dry_run;
        let service_waypoint_namespaces = service_waypoint_resource_namespaces(
            mesh,
            request.waypoint_name.as_deref(),
            &namespace,
        );
        let node_waypoint_assertors = if mesh.node_waypoint_assertors.is_empty() {
            node_waypoint_assertors_from_workloads(mesh.workloads.iter())
        } else {
            mesh.node_waypoint_assertors.clone()
        };
        // NodeWaypoint transparent-inbound-capture inventory (issue #3287).
        // Computed from the PRE-narrowing view on purpose: an enrolled pod this
        // NodeWaypoint captures for can live in another namespace, so deriving it
        // after the `workloads` narrowing below would silently drop exactly the
        // cross-namespace destinations whose PeerAuthentication posture must be
        // enforced. When the CP already resolved it (`filter_mesh_config_to_request`
        // runs BEFORE its own namespace retains and applies scope/bearer
        // authorization), that authoritative value wins; the `is_empty` fallback
        // covers the file/local source and any CP that resolved nothing, and can
        // only ever yield a SUBSET of the authorized inventory — never a widening.
        let (node_waypoint_capture_destinations, node_waypoint_capture_peer_authentications) =
            if request.node_waypoint_capture_scoping {
                let destinations = if mesh.node_waypoint_capture_destinations.is_empty() {
                    node_waypoint_capture_destinations_from_workloads(
                        mesh.workloads.iter(),
                        request.workload_spiffe_id.as_deref(),
                    )
                } else {
                    mesh.node_waypoint_capture_destinations.clone()
                };
                let candidates = if mesh.node_waypoint_capture_peer_authentications.is_empty() {
                    &mesh.peer_authentications
                } else {
                    &mesh.node_waypoint_capture_peer_authentications
                };
                let peer_authentications =
                    node_waypoint_capture_peer_authentications_for_destinations(
                        candidates.iter(),
                        &destinations,
                    );
                (destinations, peer_authentications)
            } else {
                (Vec::new(), Vec::new())
            };
        let workloads: Vec<Workload> = mesh
            .workloads
            .iter()
            .filter(|w| {
                resource_namespace_visible(&service_waypoint_namespaces, &w.namespace, &namespace)
            })
            .cloned()
            .collect();
        let effective_namespace = namespace.as_str();
        let candidate_label_sets = inferred_workload_label_sets_for_request(&workloads, &request);
        let effective_labels = if request.labels.is_empty() {
            inferred_workload_labels_for_request(&candidate_label_sets)
        } else {
            request.labels.clone()
        };
        // `effective_labels` is an ambiguous intersection (not this workload's
        // authoritative labels) precisely when no explicit request labels were
        // supplied AND several workloads share the SPIFFE id with DIVERGENT
        // label sets, so the intersection loses information. In that case
        // selector-scoped resources rode in as a candidate-any superset above,
        // and a consumer holding the real labels (the xDS DP) must re-filter
        // against them instead of trusting the intersection.
        //
        // A bare candidate count is NOT sufficient: the common replica/endpoints
        // case has many `Workload` records for one SPIFFE with IDENTICAL labels.
        // There the intersection equals every candidate set (no information
        // lost), so the inferred labels are authoritative and the marker must
        // stay false — otherwise the xDS DP would prefer its own (possibly stale
        // or partial) `FERRUM_MESH_WORKLOAD_LABELS` over the CP's correct labels
        // and could drop selector-scoped DENY/PeerAuth/JWT rules. A single
        // candidate (or concrete request labels) is likewise authoritative.
        let labels_ambiguous =
            request.labels.is_empty() && candidate_label_sets_diverge(&candidate_label_sets);
        // Candidate-any projection input for selector-scoped resources. When the
        // labels are INFERRED from an ambiguous shared-SPIFFE match, keep a
        // resource if it applies to ANY candidate workload (a superset), not
        // just the (possibly empty) label intersection: the per-pod NodeWaypoint
        // consumer re-filters against each pod's real labels, and the xDS DP
        // re-filters against its local `FERRUM_MESH_WORKLOAD_LABELS` after
        // reverse translation, so narrowing to the intersection here would drop
        // selector AuthorizationPolicies / PeerAuthentications / RequestAuthen-
        // tications those consumers still need and fail open. With concrete
        // `request.labels` there is exactly one precise set. (The mesh_authz
        // plugin tolerates the resulting superset at construction — see
        // `validate_scope_filter_identity` — and its cold-path `retain` does the
        // precise per-proxy narrowing.)
        let ambient_udp_source_workloads: Vec<Workload> = if request.ambient_udp_source_scoping {
            mesh.workloads
                .iter()
                .filter(|workload| workload.pod_uid.is_some())
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
        // Carry policy candidates for both sides of the UDP authorization
        // union. Source candidates come from the pod-UID inventory; waypoint
        // destination candidates come from the destination-visible workload
        // view and must remain present even when their pod UID was stripped at
        // the CP boundary or never existed (for example, WorkloadEntry).
        let ambient_udp_policy_candidates: Vec<(String, BTreeMap<String, String>)> =
            ambient_udp_source_workloads
                .iter()
                .chain(workloads.iter())
                .map(|workload| {
                    (
                        workload.namespace.clone(),
                        labels_to_btree(&workload.selector.labels),
                    )
                })
                .collect();
        let policy_candidate_labels: Vec<&BTreeMap<String, String>> = if request.labels.is_empty() {
            if candidate_label_sets.is_empty() {
                vec![&effective_labels]
            } else {
                candidate_label_sets.iter().collect()
            }
        } else {
            vec![&effective_labels]
        };
        // Resolve the effective applicable Sidecar egress scope for this
        // workload. The returned scope is used downstream to narrow `services`,
        // `service_entries`, and `destination_rules`. Returns `None` when no
        // Sidecar applies or when the applicable Sidecar inherits system
        // defaults with no namespace or root-namespace default to inherit
        // from. The enforcement and dry-run flags gate Sidecar resolution so
        // existing deployments see zero behavior change unless one of the
        // rollout flags is enabled.
        let resolved_sidecar = if sidecar_enforced || sidecar_dry_run {
            resolve_applicable_sidecar_egress(
                &mesh.sidecars,
                effective_namespace,
                &effective_labels,
                mesh.istio_root_namespace.as_str(),
            )
        } else {
            None
        };
        let applicable_sidecar = if sidecar_dry_run {
            None
        } else {
            resolved_sidecar
        };

        // Resolve the local workload's custom inbound listeners from the
        // applicable Sidecar's `ingress[]`. Gated like egress narrowing: only
        // under enforcement (NOT dry-run, which reports but changes nothing —
        // materializing inbound listeners is a behavior change). Resolution
        // follows the SAME tier precedence as egress, then keeps only the
        // routable entries (loopback host:port HTTP listeners); unsupported
        // shapes are dropped here and reported as deferred by the K8s status
        // writer. Carried on the slice so the DP materializer never re-resolves
        // raw `MeshSidecar` records (they do not ride the slice), mirroring the
        // `local_inbound_services` pattern.
        let (
            mut local_ingress_listeners,
            sidecar_ingress_declared,
            mut declared_ingress_http_ports,
        ): (Vec<ResolvedIngressListener>, bool, usize) = if sidecar_enforced && !sidecar_dry_run {
            resolve_applicable_sidecar_ingress(
                &mesh.sidecars,
                effective_namespace,
                &effective_labels,
                mesh.istio_root_namespace.as_str(),
            )
        } else {
            (Vec::new(), false, 0)
        };

        // Sidecar-only indexes: skip the full scan over `mesh.services` and
        // `mesh.service_entries` when no Sidecar applies (default-off feature,
        // or an enforced workload that no Sidecar resource targets). The
        // destination-rules filter is the only consumer and short-circuits
        // before reading these when `applicable_sidecar` is `None`.
        let (mesh_service_identities, service_entry_hosts) = if resolved_sidecar.is_some() {
            (
                mesh_service_identities(mesh),
                visible_service_entry_hosts(mesh, effective_namespace, &effective_labels),
            )
        } else {
            (BTreeSet::new(), BTreeSet::new())
        };

        let services: Vec<MeshService> = mesh
            .services
            .iter()
            .filter_map(|service| {
                let Some(sidecar) = applicable_sidecar else {
                    return resource_namespace_visible(
                        &service_waypoint_namespaces,
                        &service.namespace,
                        &namespace,
                    )
                    .then(|| service.clone());
                };
                narrow_service_ports(service, sidecar, &cluster_domain)
            })
            .collect();
        // Inbound serving must not be gated by egress scope. When a Sidecar
        // narrows `services`/`workloads` (egress narrowing can drop or port-trim
        // the workload's own service; identity narrowing can drop the local
        // workload itself), capture the LOCAL workload(s) and their own
        // service(s) **un-narrowed** in separate inbound-only views — never
        // folded into `services`/`workloads`, so the egress/outbound-registry
        // view is unchanged. The local workload is identified by
        // `resolve_local_workloads` (SPIFFE + non-vacuous label/cluster match,
        // with a shared-SPIFFE ambiguity guard).
        //
        // Resolution is factored into one closure so the ingress path can reuse
        // it INDEPENDENTLY of egress-scope inheritance (a Sidecar that declares
        // only `ingress[]` usually omits `spec.egress` → `egress_inherits_defaults`,
        // which can resolve no egress scope and leave `applicable_sidecar` `None`,
        // yet its ingress listeners were still resolved and need a local-service
        // anchor). The closure borrows the workload sets immutably and is pure.
        let resolve_local_inbound = |spiffe: &str| -> (Vec<Workload>, Vec<MeshService>) {
            let local_cluster = mesh
                .multi_cluster
                .as_ref()
                .and_then(|mc| mc.local_cluster.as_deref());
            let local_workloads: Vec<Workload> =
                resolve_local_workloads(&workloads, spiffe, &effective_labels, local_cluster)
                    .into_iter()
                    .cloned()
                    .collect();
            let local_keys: BTreeSet<(&str, &str)> = local_workloads
                .iter()
                .map(|w| (w.service_name.as_str(), w.namespace.as_str()))
                .collect();
            let services = mesh
                .services
                .iter()
                .filter(|s| {
                    local_keys.contains(&(s.name.as_str(), s.namespace.as_str()))
                        && resource_namespace_visible(
                            &service_waypoint_namespaces,
                            &s.namespace,
                            &namespace,
                        )
                })
                .cloned()
                .collect::<Vec<_>>();
            (local_workloads, services)
        };

        // Egress-narrowing inbound view: only needed when egress narrowing is
        // active; otherwise the full `services`/`workloads` are intact and the
        // materializer falls back to them.
        // `local_inbound_workloads` is `Some` exactly when narrowing was active
        // and we resolved (or ambiguously failed to resolve) the local identity;
        // it then gates the materializer, which must NOT fall back to the
        // narrowed `workloads`. `None` means no narrowing — full sets are intact.
        let (mut local_inbound_workloads, mut local_inbound_services): (
            Option<Vec<Workload>>,
            Vec<MeshService>,
        ) = match request.workload_spiffe_id.as_deref() {
            Some(spiffe) if applicable_sidecar.is_some() => {
                let (local_workloads, services) = resolve_local_inbound(spiffe);
                (Some(local_workloads), services)
            }
            _ => (None, Vec::new()),
        };

        // F6 §6.2 (decouple ingress from egress scope): an ingress-only Sidecar
        // may have resolved listeners (or declared ingress) while egress scope
        // resolved to none (`applicable_sidecar` `None`) — so the block above
        // left `local_inbound_services` empty. Resolve the local-inbound view
        // here from the workload SPIFFE id INDEPENDENTLY, so the listeners get a
        // host anchor (and the materializer/router see the local service) without
        // an egress scope having been applied. Never folds into the egress
        // `services`/`workloads` view. Skipped when egress already resolved it
        // (re-resolving would be redundant) or there is no ingress to anchor.
        if (sidecar_ingress_declared || !local_ingress_listeners.is_empty())
            && local_inbound_services.is_empty()
            && let Some(spiffe) = request.workload_spiffe_id.as_deref()
        {
            let (local_workloads, services) = resolve_local_inbound(spiffe);
            // `Some` marks the local-inbound view as AUTHORITATIVE (the
            // materializer must not fall back to the narrowed `workloads`),
            // mirroring the egress-narrowed branch above. Set only when we
            // actually resolved a view here (a `None` from the egress branch
            // means "no narrowing"; promoting it to `Some(empty)` would wrongly
            // suppress the default fallback for a workload with no ingress).
            local_inbound_workloads = Some(local_workloads);
            local_inbound_services = services;
        }

        // Stamp the ingress listeners with the owning local service identity
        // (the first resolved local-inbound service). Both the inbound
        // materializer and the router/validator derive the listener proxy id
        // forward from these fields (`mesh_ingress_proxy_id`), so they stay in
        // lock-step without re-running local-workload resolution. When no local
        // service resolved (e.g. EndpointSlice lag), drop the listeners — they
        // have no host identity to anchor and the materializer would skip them
        // fail-closed anyway. (The `sidecar_ingress_declared` marker still rides
        // the slice, so the materializer fails closed — no default routes — even
        // when the anchor is missing and the listener list is empty.)
        if !local_ingress_listeners.is_empty() {
            match local_inbound_services.first() {
                Some(service) => {
                    for listener in &mut local_ingress_listeners {
                        listener.owner_namespace = service.namespace.clone();
                        listener.owner_service = service.name.clone();
                    }
                }
                None => {
                    debug!(
                        "Sidecar ingress[] resolved but no local service available to anchor \
                         listener identity; dropping ingress listeners"
                    );
                    local_ingress_listeners.clear();
                    // No listeners can materialize without an anchor, so the
                    // router forms no ingress group; zero the declared port count
                    // so a phantom count never rides the slice/carrier. The
                    // `sidecar_ingress_declared` marker still suppresses the
                    // default inbound routes (fail-closed).
                    declared_ingress_http_ports = 0;
                }
            }
        }

        let mesh_policies: Vec<MeshPolicy> = mesh
            .mesh_policies
            .iter()
            .filter(|policy| {
                (!ambient_udp_policy_candidates.is_empty()
                    && ambient_udp_policy_candidates
                        .iter()
                        .any(|(candidate_namespace, labels)| {
                            policy_scope_applies_to_workload(policy, candidate_namespace, labels)
                        }))
                    || policy_candidate_labels.iter().any(|labels| {
                        policy_scope_applies_to_workload(policy, effective_namespace, *labels)
                    })
            })
            .cloned()
            .collect();
        let peer_authentications: Vec<PeerAuthentication> = mesh
            .peer_authentications
            .iter()
            .filter(|peer_auth| {
                policy_candidate_labels.iter().any(|labels| {
                    peer_auth_applies_to_workload(peer_auth, effective_namespace, *labels)
                })
            })
            .cloned()
            .collect();
        let service_entries: Vec<ServiceEntry> = mesh
            .service_entries
            .iter()
            .filter(|entry| {
                service_entry_applies_to_workload(entry, effective_namespace, &effective_labels)
            })
            .flat_map(|entry| {
                let Some(sidecar) = applicable_sidecar else {
                    return vec![entry.clone()];
                };
                narrow_service_entry_ports(entry, sidecar)
            })
            .collect();
        let request_authentications: Vec<MeshRequestAuthentication> = mesh
            .request_authentications
            .iter()
            .filter(|ra| {
                policy_candidate_labels.iter().any(|labels| {
                    scope_applies_to_workload(&ra.scope, effective_namespace, *labels)
                })
            })
            .cloned()
            .collect();
        let telemetry_resources: Vec<MeshTelemetryResource> = mesh
            .telemetry_resources
            .iter()
            .filter(|t| {
                policy_candidate_labels
                    .iter()
                    .any(|labels| scope_applies_to_workload(&t.scope, effective_namespace, *labels))
            })
            .cloned()
            .collect();
        let destination_rules: Vec<MeshDestinationRule> = mesh
            .destination_rules
            .iter()
            .filter(|dr| {
                let Some(sidecar) = applicable_sidecar else {
                    return resource_namespace_visible(
                        &service_waypoint_namespaces,
                        &dr.namespace,
                        &namespace,
                    );
                };
                let (resource_namespace, host_candidates) = destination_rule_host_scope(
                    dr,
                    &cluster_domain,
                    &mesh_service_identities,
                    &service_entry_hosts,
                );
                // Istio DestinationRule lookup namespaces are {client (the
                // workload's own namespace), target service namespace, root
                // namespace}. Root-namespace plumbing is deferred (see
                // docs/mesh.md "Known Limitations"), so admit only DRs
                // declared in the client or the target service namespace.
                // Without this guard a DR in an unrelated namespace
                // targeting `reviews.beta` could be imported into an
                // `alpha` workload's slice merely because the Sidecar
                // admits `beta/*`, letting a third-party namespace override
                // client traffic policy.
                let dr_namespace = dr.namespace.as_str();
                if dr_namespace != effective_namespace
                    && dr_namespace != resource_namespace.as_str()
                {
                    return false;
                }
                let host_refs: Vec<&str> = host_candidates.iter().map(String::as_str).collect();
                sidecar_egress_includes_service(
                    sidecar.namespace,
                    sidecar.egress,
                    &resource_namespace,
                    &host_refs,
                    None,
                )
            })
            .cloned()
            .collect();
        // VirtualService-derived CORS policies narrow EXACTLY like
        // DestinationRules: same namespace-visibility default, same
        // client-or-target-namespace guard, same Sidecar egress-scope check —
        // both are host-targeting client-side traffic policy, so a namespace
        // that cannot override a workload's DRs must not be able to inject
        // CORS behavior onto its routes either.
        let virtual_service_cors_policies: Vec<MeshVirtualServiceCorsPolicy> = mesh
            .virtual_service_cors_policies
            .iter()
            .filter(|policy| {
                // `exportTo` IS the visibility mechanism for VirtualService
                // policy (ServiceEntry semantics — NOT the plain
                // namespace-visibility rule DRs use, which would hide a public
                // `exportTo: ['*']` policy declared in the target service's
                // namespace): a namespace-local `exportTo: ['.']` never leaks
                // onto another namespace's outbound routes, and `*` /
                // explicit-namespace grants cross namespaces.
                if !virtual_service_cors_policy_exported_to_namespace(policy, effective_namespace) {
                    return false;
                }
                let Some(sidecar) = applicable_sidecar else {
                    return true;
                };
                let (resource_namespace, host_candidates) = policy_host_scope(
                    &policy.host,
                    &policy.namespace,
                    &cluster_domain,
                    &mesh_service_identities,
                    &service_entry_hosts,
                );
                let policy_namespace = policy.namespace.as_str();
                if policy_namespace != effective_namespace
                    && policy_namespace != resource_namespace.as_str()
                {
                    return false;
                }
                let host_refs: Vec<&str> = host_candidates.iter().map(String::as_str).collect();
                sidecar_egress_includes_service(
                    sidecar.namespace,
                    sidecar.egress,
                    &resource_namespace,
                    &host_refs,
                    None,
                )
            })
            .cloned()
            .collect();
        let proxy_configs: Vec<MeshProxyConfig> = mesh
            .proxy_configs
            .iter()
            .filter(|pc| {
                proxy_config_applies_to_workload(pc, effective_namespace, &effective_labels)
            })
            .cloned()
            .collect();
        let extension_configs: Vec<MeshExtensionConfig> = mesh
            .extension_configs
            .iter()
            .filter(|ext| {
                resource_namespace_visible(
                    &service_waypoint_namespaces,
                    &ext.namespace,
                    effective_namespace,
                )
            })
            .cloned()
            .collect();
        let workloads =
            if request.enforce_sidecar_identity_narrowing && applicable_sidecar.is_some() {
                narrow_workload_identities(workloads, &services, &request)
            } else {
                workloads
            };

        let sidecar_egress_scope = resolved_sidecar.map(|sidecar| {
            build_sidecar_egress_scope_snapshot(EgressScopeBuildContext {
                mesh,
                sidecar,
                workload_namespace: effective_namespace,
                workload_labels: &effective_labels,
                cluster_domain: &cluster_domain,
                mesh_service_identities: &mesh_service_identities,
                service_entry_hosts: &service_entry_hosts,
                sidecar_enforced,
                dry_run: sidecar_dry_run,
            })
        });

        let waypoint_resources = ServiceWaypointNarrowingResources {
            services,
            service_entries,
            destination_rules,
            workloads,
            mesh_policies,
        };
        let ServiceWaypointNarrowingResources {
            services,
            service_entries,
            destination_rules,
            workloads,
            mesh_policies,
        } = if let Some(waypoint) = request.waypoint_name.as_deref() {
            narrow_for_service_waypoint(
                waypoint,
                &request.namespace,
                &request.cluster_domain,
                &mesh.waypoint_bindings,
                waypoint_resources,
            )
        } else {
            waypoint_resources
        };

        // Bind `request.namespace` so we can both move it into `self` and
        // borrow it inside the `multi_cluster` `.retain` closure below without
        // E0382. `String: Clone` is cheap relative to a slice-apply cycle and
        // happens once per slice; the alternative (reordering field
        // initialization) is fragile across future struct changes.
        let request_namespace = request.namespace;
        Self {
            node_id: request.node_id,
            namespace: request_namespace.clone(),
            workload_spiffe_id: request.workload_spiffe_id,
            waypoint_name: request.waypoint_name,
            labels: effective_labels,
            labels_ambiguous,
            version,
            revision,
            workloads,
            ambient_udp_source_workloads,
            node_waypoint_assertors,
            node_waypoint_capture_destinations,
            node_waypoint_capture_peer_authentications,
            services,
            local_inbound_services,
            local_inbound_workloads,
            local_ingress_listeners,
            sidecar_ingress_declared,
            declared_ingress_http_ports,
            mesh_policies,
            peer_authentications,
            service_entries,
            request_authentications,
            telemetry_resources,
            destination_rules,
            virtual_service_cors_policies,
            proxy_configs,
            trust_bundles: mesh.trust_bundles.clone(),
            multi_cluster: mesh.multi_cluster.as_ref().map(|multi_cluster| {
                let mut scoped = multi_cluster.clone();
                scoped
                    .east_west_gateways
                    .retain(|gateway| gateway.namespace == request_namespace);
                scoped
            }),
            outbound_traffic_policy: resolve_effective_outbound_traffic_policy(
                mesh,
                effective_namespace,
                &effective_labels,
            ),
            sidecar_egress_scope,
            extension_configs,
            // The canonical GatewayConfig has no declarative RTDS surface.
            // xDS reverse translation populates this field directly; native
            // MeshSubscribe configs leave it empty.
            runtime_overlay: MeshRuntimeOverlay::default(),
        }
    }
}

/// Narrow slice resources to those bound to the named GAMMA Waypoint.
///
/// Returns the input vectors unchanged when no binding for `waypoint_name`
/// exists (the slice falls back to whatever the workload-scope filter
/// already produced — fail-open is intentional for the rollout window, so
/// an operator who flips `FERRUM_MESH_TOPOLOGY=service_waypoint` before
/// the matching `Gateway` resource lands does not see immediate service
/// loss). When at least one binding matches, services and dependent
/// resources are filtered to only those in the binding's `services` list.
struct ServiceWaypointNarrowingResources {
    services: Vec<MeshService>,
    service_entries: Vec<ServiceEntry>,
    destination_rules: Vec<MeshDestinationRule>,
    workloads: Vec<Workload>,
    mesh_policies: Vec<MeshPolicy>,
}

fn service_waypoint_resource_namespaces(
    mesh: &MeshConfig,
    waypoint_name: Option<&str>,
    waypoint_namespace: &str,
) -> Option<BTreeSet<String>> {
    let waypoint_name = waypoint_name?;
    let binding = mesh
        .waypoint_bindings
        .iter()
        .find(|b| b.name == waypoint_name && b.namespace == waypoint_namespace)?;
    let mut namespaces = BTreeSet::new();
    namespaces.insert(waypoint_namespace.to_string());
    namespaces.extend(
        binding
            .services
            .iter()
            .map(|service| service.namespace.clone()),
    );
    Some(namespaces)
}

fn resource_namespace_visible(
    service_waypoint_namespaces: &Option<BTreeSet<String>>,
    resource_namespace: &str,
    request_namespace: &str,
) -> bool {
    service_waypoint_namespaces
        .as_ref()
        .map_or(resource_namespace == request_namespace, |namespaces| {
            namespaces.contains(resource_namespace)
        })
}

fn narrow_for_service_waypoint(
    waypoint_name: &str,
    waypoint_namespace: &str,
    cluster_domain: &str,
    bindings: &[crate::modes::mesh::config::MeshWaypointBinding],
    resources: ServiceWaypointNarrowingResources,
) -> ServiceWaypointNarrowingResources {
    let Some(binding) = bindings
        .iter()
        .find(|b| b.name == waypoint_name && b.namespace == waypoint_namespace)
    else {
        return resources;
    };
    if binding.waypoint_for.eq_ignore_ascii_case("none") {
        // Operator explicitly opted out — narrow to an empty admitted set.
        return ServiceWaypointNarrowingResources {
            services: Vec::new(),
            service_entries: Vec::new(),
            destination_rules: Vec::new(),
            workloads: Vec::new(),
            mesh_policies: resources.mesh_policies,
        };
    }

    let bound: BTreeSet<(String, String)> = binding
        .services
        .iter()
        .map(|s| (s.namespace.clone(), s.name.clone()))
        .collect();
    let admitted_services: Vec<MeshService> = resources
        .services
        .into_iter()
        .filter(|s| bound.contains(&(s.namespace.clone(), s.name.clone())))
        .collect();
    let admitted_hosts = admitted_service_hosts(&admitted_services, cluster_domain);
    let admitted_destination_rules: Vec<MeshDestinationRule> = resources
        .destination_rules
        .into_iter()
        .filter(|dr| {
            // DR is admitted only when its host is one of the admitted
            // Service's canonical Kubernetes DNS aliases. Broad prefix
            // matches can accidentally admit unrelated external hosts.
            destination_rule_matches_admitted_service(
                dr,
                waypoint_namespace,
                cluster_domain,
                &admitted_services,
                &admitted_hosts,
            )
        })
        .collect();
    let admitted_service_entries: Vec<ServiceEntry> = resources
        .service_entries
        .into_iter()
        .filter(|se| {
            // ServiceEntry hosts can be arbitrary; admit only canonical
            // aliases for bound Services. External-looking hosts that happen
            // to start with `{service}.{namespace}.` are unrelated.
            se.hosts.iter().any(|h| {
                let h = h.trim_end_matches('.');
                host_matches_admitted_service(h, &admitted_hosts)
            })
        })
        .collect();
    let admitted_workloads: Vec<Workload> = resources
        .workloads
        .into_iter()
        .filter(|w| {
            // Admit any workload whose addresses or SPIFFE identity is
            // referenced by an admitted service's `workloads[]` list. This
            // preserves the per-pod identity routing fans-out from the
            // narrowed service set without bringing in unrelated pods.
            let spiffe = &w.spiffe_id;
            admitted_services
                .iter()
                .any(|svc| svc.workloads.iter().any(|wref| &wref.spiffe_id == spiffe))
        })
        .collect();
    ServiceWaypointNarrowingResources {
        services: admitted_services,
        service_entries: admitted_service_entries,
        destination_rules: admitted_destination_rules,
        workloads: admitted_workloads,
        mesh_policies: resources.mesh_policies,
    }
}

fn admitted_service_hosts(services: &[MeshService], cluster_domain: &str) -> BTreeSet<String> {
    let cluster_domain = cluster_domain.trim().trim_end_matches('.');
    let mut hosts = BTreeSet::new();
    for service in services {
        hosts.insert(format!("{}.{}", service.name, service.namespace));
        hosts.insert(format!("{}.{}.svc", service.name, service.namespace));
        if !cluster_domain.is_empty() {
            hosts.insert(format!(
                "{}.{}.svc.{}",
                service.name, service.namespace, cluster_domain
            ));
        }
    }
    hosts
}

fn destination_rule_matches_admitted_service(
    dr: &MeshDestinationRule,
    waypoint_namespace: &str,
    cluster_domain: &str,
    admitted_services: &[MeshService],
    admitted_hosts: &BTreeSet<String>,
) -> bool {
    let host = dr.host.trim_end_matches('.');
    host_matches_admitted_service(host, admitted_hosts)
        && destination_rule_namespace_allowed_for_admitted_service(
            dr,
            waypoint_namespace,
            cluster_domain,
            admitted_services,
            host,
        )
        || admitted_services
            .iter()
            .any(|service| host == service.name && dr.namespace == service.namespace)
}

fn destination_rule_namespace_allowed_for_admitted_service(
    dr: &MeshDestinationRule,
    waypoint_namespace: &str,
    cluster_domain: &str,
    admitted_services: &[MeshService],
    host: &str,
) -> bool {
    let cluster_domain = cluster_domain.trim().trim_end_matches('.');
    admitted_services.iter().any(|service| {
        let host_matches = host == format!("{}.{}", service.name, service.namespace)
            || host == format!("{}.{}.svc", service.name, service.namespace)
            || (!cluster_domain.is_empty()
                && host
                    == format!(
                        "{}.{}.svc.{}",
                        service.name, service.namespace, cluster_domain
                    ));
        host_matches && (dr.namespace == service.namespace || dr.namespace == waypoint_namespace)
    })
}

fn host_matches_admitted_service(host: &str, admitted_hosts: &BTreeSet<String>) -> bool {
    admitted_hosts.contains(host.trim_end_matches('.'))
}

/// Filter `workloads` down to identities referenced by admitted services.
///
/// The local workload running this sidecar is usually not in any admitted
/// service's `workloads[]` and can therefore be removed from `slice.workloads`.
/// Consumers that need the local identity must read `MeshSlice::workload_spiffe_id`
/// or use `inferred_workload_labels_for_request`, which runs before narrowing.
///
/// Inbound mTLS peer validation uses `slice.trust_bundles`, and HBONE
/// `source.principal` baggage uses peer-cert trust-domain matching plus
/// `FERRUM_MESH_TRUST_DOMAIN_ALIASES`, so neither depends on this list.
fn narrow_workload_identities(
    workloads: Vec<Workload>,
    admitted_services: &[MeshService],
    request: &MeshSliceRequest,
) -> Vec<Workload> {
    let admitted_service_keys: HashSet<_> = admitted_services
        .iter()
        .map(|service| (service.namespace.as_str(), service.name.as_str()))
        .collect();
    let reachable_workloads: HashSet<(&str, &str, &SpiffeId)> = admitted_services
        .iter()
        .flat_map(|service| {
            service.workloads.iter().map(move |workload| {
                (
                    service.namespace.as_str(),
                    service.name.as_str(),
                    &workload.spiffe_id,
                )
            })
        })
        .collect();
    if !admitted_services.is_empty() && reachable_workloads.is_empty() {
        warn!(
            node_id = request.node_id.as_str(),
            namespace = request.namespace.as_str(),
            workload_spiffe_id = request.workload_spiffe_id.as_deref().unwrap_or(""),
            admitted_services = admitted_services.len(),
            "Sidecar workload identity narrowing found no reachable identities; admitted MeshService.workloads lists are empty"
        );
    } else if admitted_services.is_empty() {
        debug!(
            node_id = request.node_id.as_str(),
            namespace = request.namespace.as_str(),
            workload_spiffe_id = request.workload_spiffe_id.as_deref().unwrap_or(""),
            "Sidecar workload identity narrowing found no admitted services; slice workloads will be empty"
        );
    }
    workloads
        .into_iter()
        .filter(|workload| {
            admitted_service_keys
                .contains(&(workload.namespace.as_str(), workload.service_name.as_str()))
                && reachable_workloads.contains(&(
                    workload.namespace.as_str(),
                    workload.service_name.as_str(),
                    &workload.spiffe_id,
                ))
        })
        .collect()
}

fn inferred_workload_label_sets_for_request(
    workloads: &[Workload],
    request: &MeshSliceRequest,
) -> Vec<BTreeMap<String, String>> {
    let Some(spiffe_id) = request.workload_spiffe_id.as_deref() else {
        return Vec::new();
    };
    let matches: Vec<BTreeMap<String, String>> = workloads
        .iter()
        .filter(|workload| workload.spiffe_id.as_str() == spiffe_id)
        .map(|workload| labels_to_btree(&workload.selector.labels))
        .collect();
    if matches.len() > 1 {
        warn!(
            node_id = %request.node_id,
            namespace = %request.namespace,
            workload_spiffe_id = %spiffe_id,
            matched_workloads = matches.len(),
            "Mesh slice request matched multiple workloads with the same SPIFFE ID; explicit workload labels are required for deterministic selector scoping"
        );
    }
    matches
}

/// Whether the candidate label sets for a shared SPIFFE actually diverge, so
/// that their intersection ([`inferred_workload_labels_for_request`]) loses
/// information and cannot be trusted as the workload's authoritative labels.
///
/// Returns `false` for zero/one candidate and for the common replica case where
/// every matching `Workload` carries the SAME labels: there the intersection
/// equals each set and is authoritative. Only genuinely divergent sets (where a
/// selector policy may match one candidate but not another) make the labels
/// ambiguous and require a label-holding consumer to re-filter the superset.
fn candidate_label_sets_diverge(candidate_label_sets: &[BTreeMap<String, String>]) -> bool {
    let mut iter = candidate_label_sets.iter();
    let Some(first) = iter.next() else {
        return false;
    };
    iter.any(|labels| labels != first)
}

fn inferred_workload_labels_for_request(
    candidate_label_sets: &[BTreeMap<String, String>],
) -> BTreeMap<String, String> {
    let Some(first) = candidate_label_sets.first() else {
        return BTreeMap::new();
    };
    let mut common_labels = first.clone();
    for labels in candidate_label_sets.iter().skip(1) {
        common_labels
            .retain(|key, value| labels.get(key).is_some_and(|candidate| candidate == value));
    }
    common_labels
}

fn normalize_known_destination_host(value: &str) -> Option<String> {
    let value = value.trim().trim_matches('.').to_ascii_lowercase();
    if value.is_empty() {
        return None;
    }
    if value.starts_with('[') {
        if value.ends_with(']')
            && let Ok(IpAddr::V6(addr)) = value[1..value.len() - 1].parse::<IpAddr>()
        {
            return Some(format!("[{addr}]"));
        }
        return Some(value);
    }
    if let Ok(IpAddr::V6(addr)) = value.parse::<IpAddr>() {
        return Some(format!("[{addr}]"));
    }
    Some(value)
}

fn insert_known_destination(
    entries: &mut HashSet<String>,
    host: &str,
    ports: impl Iterator<Item = u16>,
) {
    entries.insert(host.to_string());
    let mut inserted_port = false;
    for port in ports {
        inserted_port = true;
        entries.insert(format!("{host}:{port}"));
    }
    if !inserted_port {
        entries.insert(format!("{host}:*"));
    }
}

struct EgressScopeBuildContext<'a, L: WorkloadLabels + ?Sized> {
    mesh: &'a MeshConfig,
    sidecar: ResolvedSidecarEgress<'a>,
    workload_namespace: &'a str,
    workload_labels: &'a L,
    cluster_domain: &'a str,
    mesh_service_identities: &'a BTreeSet<(String, String)>,
    service_entry_hosts: &'a BTreeSet<String>,
    sidecar_enforced: bool,
    dry_run: bool,
}

fn build_sidecar_egress_scope_snapshot<L: WorkloadLabels + ?Sized>(
    ctx: EgressScopeBuildContext<'_, L>,
) -> MeshEgressScopeSnapshot {
    let EgressScopeBuildContext {
        mesh,
        sidecar,
        workload_namespace,
        workload_labels,
        cluster_domain,
        mesh_service_identities,
        service_entry_hosts,
        sidecar_enforced,
        dry_run,
    } = ctx;
    let scoped_services: Vec<MeshService> = mesh
        .services
        .iter()
        .filter_map(|service| narrow_service_ports(service, sidecar, cluster_domain))
        .collect();
    let scoped_service_entries: Vec<ServiceEntry> = mesh
        .service_entries
        .iter()
        .filter(|entry| {
            service_entry_applies_to_workload(entry, workload_namespace, workload_labels)
        })
        .flat_map(|entry| narrow_service_entry_ports(entry, sidecar))
        .collect();
    let scoped_workloads: Vec<Workload> = mesh
        .workloads
        .iter()
        .filter(|workload| workload.namespace == workload_namespace)
        .cloned()
        .collect();
    let scoped_destination_rules: Vec<MeshDestinationRule> = mesh
        .destination_rules
        .iter()
        .filter(|dr| {
            let (resource_namespace, host_candidates) = destination_rule_host_scope(
                dr,
                cluster_domain,
                mesh_service_identities,
                service_entry_hosts,
            );
            let dr_namespace = dr.namespace.as_str();
            if dr_namespace != workload_namespace && dr_namespace != resource_namespace.as_str() {
                return false;
            }
            let host_refs: Vec<&str> = host_candidates.iter().map(String::as_str).collect();
            sidecar_egress_includes_service(
                sidecar.namespace,
                sidecar.egress,
                &resource_namespace,
                &host_refs,
                None,
            )
        })
        .cloned()
        .collect();

    let baseline_local_services = mesh
        .services
        .iter()
        .filter(|service| service.namespace == workload_namespace)
        .count();
    let admitted_local_services = scoped_services
        .iter()
        .filter(|service| service.namespace == workload_namespace)
        .count();
    let baseline_local_destination_rules = mesh
        .destination_rules
        .iter()
        .filter(|dr| dr.namespace == workload_namespace)
        .count();
    let admitted_local_destination_rules = scoped_destination_rules
        .iter()
        .filter(|dr| dr.namespace == workload_namespace)
        .count();
    let destination_rule_resources: Vec<MeshEgressScopeResource> = scoped_destination_rules
        .iter()
        .map(destination_rule_scope_resource)
        .collect();
    let scope_slice = MeshSlice {
        namespace: workload_namespace.to_string(),
        workloads: scoped_workloads,
        services: scoped_services.clone(),
        service_entries: scoped_service_entries.clone(),
        destination_rules: scoped_destination_rules,
        outbound_traffic_policy: mesh.outbound_traffic_policy,
        ..MeshSlice::default()
    };

    MeshEgressScopeSnapshot {
        sidecar_enforced,
        dry_run,
        sidecar_applied: sidecar_enforced && !dry_run,
        sidecar_admitted_services: admitted_local_services,
        sidecar_denied_services: baseline_local_services.saturating_sub(admitted_local_services),
        sidecar_admitted_destination_rules: admitted_local_destination_rules,
        sidecar_denied_destination_rules: baseline_local_destination_rules
            .saturating_sub(admitted_local_destination_rules),
        destination_rules: destination_rule_resources,
        services: scoped_services
            .iter()
            .map(|service| mesh_service_scope_resource(service, cluster_domain))
            .collect(),
        service_entries: scoped_service_entries
            .iter()
            .map(service_entry_scope_resource)
            .collect(),
        known_destinations: scope_slice.build_known_destinations(cluster_domain),
    }
}

fn destination_rule_scope_resource(rule: &MeshDestinationRule) -> MeshEgressScopeResource {
    MeshEgressScopeResource {
        namespace: rule.namespace.clone(),
        name: rule.name.clone(),
        hosts: vec![rule.host.clone()],
        ports: Vec::new(),
    }
}

fn mesh_service_scope_resource(
    service: &MeshService,
    cluster_domain: &str,
) -> MeshEgressScopeResource {
    let mut hosts = mesh_service_host_candidates(service, cluster_domain);
    hosts.sort();
    hosts.dedup();
    let mut ports: Vec<u16> = service.ports.iter().map(|port| port.port).collect();
    ports.sort_unstable();
    ports.dedup();
    MeshEgressScopeResource {
        namespace: service.namespace.clone(),
        name: service.name.clone(),
        hosts,
        ports,
    }
}

fn service_entry_scope_resource(entry: &ServiceEntry) -> MeshEgressScopeResource {
    let mut hosts = entry.hosts.clone();
    hosts.sort();
    hosts.dedup();
    let mut ports: Vec<u16> = entry.ports.iter().map(|port| port.port).collect();
    ports.sort_unstable();
    ports.dedup();
    MeshEgressScopeResource {
        namespace: entry.namespace.clone(),
        name: entry.name.clone(),
        hosts,
        ports,
    }
}

fn mesh_service_identities(mesh: &MeshConfig) -> BTreeSet<(String, String)> {
    let mut identities = BTreeSet::new();
    for service in &mesh.services {
        let namespace = service
            .namespace
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let name = service
            .name
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if !namespace.is_empty() && !name.is_empty() {
            identities.insert((namespace, name));
        }
    }
    identities
}

fn visible_service_entry_hosts<L: WorkloadLabels + ?Sized>(
    mesh: &MeshConfig,
    workload_namespace: &str,
    workload_labels: &L,
) -> BTreeSet<String> {
    let mut hosts = BTreeSet::new();
    for entry in &mesh.service_entries {
        if !service_entry_applies_to_workload(entry, workload_namespace, workload_labels) {
            continue;
        }
        for host in &entry.hosts {
            let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
            if !host.is_empty() {
                hosts.insert(host);
            }
        }
    }
    hosts
}

fn mesh_service_host_candidates(service: &MeshService, cluster_domain: &str) -> Vec<String> {
    service_host_aliases(&service.name, &service.namespace, cluster_domain)
}

fn service_host_aliases(name: &str, namespace: &str, cluster_domain: &str) -> Vec<String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let namespace = namespace.trim().trim_end_matches('.').to_ascii_lowercase();
    let cluster_domain = cluster_domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let mut candidates = vec![
        name.clone(),
        format!("{name}.{namespace}"),
        format!("{name}.{namespace}.svc"),
    ];
    if !cluster_domain.is_empty() {
        candidates.push(format!("{name}.{namespace}.svc.{cluster_domain}"));
    }
    candidates
}

fn destination_rule_host_scope(
    rule: &MeshDestinationRule,
    cluster_domain: &str,
    mesh_service_identities: &BTreeSet<(String, String)>,
    service_entry_hosts: &BTreeSet<String>,
) -> (String, Vec<String>) {
    policy_host_scope(
        &rule.host,
        &rule.namespace,
        cluster_domain,
        mesh_service_identities,
        service_entry_hosts,
    )
}

/// Resolve a host-targeting policy's `(host, namespace)` pair to the target
/// service's namespace plus the host alias set. Shared by DestinationRule
/// narrowing and VirtualService-CORS narrowing so a policy host is scoped
/// with ONE set of semantics.
fn policy_host_scope(
    policy_host: &str,
    policy_namespace: &str,
    cluster_domain: &str,
    mesh_service_identities: &BTreeSet<(String, String)>,
    service_entry_hosts: &BTreeSet<String>,
) -> (String, Vec<String>) {
    let host = policy_host
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let rule_namespace = policy_namespace
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let cluster_domain = cluster_domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();

    destination_rule_service_ref_from_host(
        &host,
        &rule_namespace,
        &cluster_domain,
        mesh_service_identities,
        service_entry_hosts,
    )
    .map(|(service_name, service_namespace)| {
        let candidates = service_host_aliases(&service_name, &service_namespace, &cluster_domain);
        (service_namespace, candidates)
    })
    .unwrap_or_else(|| (rule_namespace, vec![host]))
}

fn destination_rule_service_ref_from_host(
    host: &str,
    rule_namespace: &str,
    cluster_domain: &str,
    mesh_service_identities: &BTreeSet<(String, String)>,
    service_entry_hosts: &BTreeSet<String>,
) -> Option<(String, String)> {
    if host.is_empty() || rule_namespace.is_empty() || host.contains('*') {
        return None;
    }
    if service_entry_hosts.contains(host) {
        return None;
    }
    if !host.contains('.') {
        return Some((host.to_string(), rule_namespace.to_string()));
    }

    if let Some((name, namespace)) = split_canonical_service_host(host)
        && mesh_service_identity_exists(mesh_service_identities, namespace, name)
    {
        return Some((name.to_string(), namespace.to_string()));
    }

    if let Some((name, namespace)) = host
        .strip_suffix(".svc")
        .and_then(split_canonical_service_host)
    {
        return Some((name.to_string(), namespace.to_string()));
    }

    if !cluster_domain.is_empty()
        && let Some((name, namespace)) = host
            .strip_suffix(&format!(".svc.{cluster_domain}"))
            .and_then(split_canonical_service_host)
    {
        return Some((name.to_string(), namespace.to_string()));
    }

    None
}

fn mesh_service_identity_exists(
    mesh_service_identities: &BTreeSet<(String, String)>,
    namespace: &str,
    name: &str,
) -> bool {
    mesh_service_identities.contains(&(namespace.to_string(), name.to_string()))
}

fn split_canonical_service_host(host: &str) -> Option<(&str, &str)> {
    let mut labels = host.split('.');
    let name = labels.next()?;
    let namespace = labels.next()?;
    if labels.next().is_some() || name.is_empty() || namespace.is_empty() {
        return None;
    }
    Some((name, namespace))
}

/// Resolve the most-specific applicable Sidecar for a workload.
///
/// Most specific wins: a Sidecar with a non-empty `workload_selector` in the
/// workload namespace whose labels match the workload outranks a root-namespace
/// Sidecar with an explicitly mesh-wide selector, which outranks the workload
/// namespace-default Sidecar (no `workload_selector`), which outranks the Istio
/// root-namespace default Sidecar. Within the same tier the ASCII-smallest name
/// wins so reconciles stay deterministic.
///
/// Returns `None` if no Sidecar in `sidecars` applies to the workload.
fn resolve_applicable_sidecar_egress<'a, L: WorkloadLabels + ?Sized>(
    sidecars: &'a [MeshSidecar],
    workload_namespace: &'a str,
    workload_labels: &L,
    istio_root_namespace: &str,
) -> Option<ResolvedSidecarEgress<'a>> {
    // Collect all matching sidecars per tier, then pick the ASCII-smallest
    // `name` as a deterministic tiebreak. Translator emission order is not
    // a stable input — two equally-applicable Sidecars in the same tier must
    // resolve to the same result across pods and reconciles. This matches
    // the precedent set by `MeshSlice::resolved_proxy_config`.
    let mut workload_scoped: Option<&MeshSidecar> = None;
    let mut root_workload_scoped: Option<&MeshSidecar> = None;
    let mut namespace_default: Option<&MeshSidecar> = None;
    let mut root_namespace_default: Option<&MeshSidecar> = None;
    let root_namespace = istio_root_namespace.trim();

    for sidecar in sidecars {
        if sidecar.namespace == workload_namespace {
            match sidecar.workload_selector.as_ref() {
                Some(selector) if !selector.labels.is_empty() => {
                    if workload_selector_matches(selector, workload_namespace, workload_labels)
                        && workload_scoped
                            .map(|current| sidecar.name.as_str() < current.name.as_str())
                            .unwrap_or(true)
                    {
                        workload_scoped = Some(sidecar);
                    }
                }
                _ => {
                    if namespace_default
                        .map(|current| sidecar.name.as_str() < current.name.as_str())
                        .unwrap_or(true)
                    {
                        namespace_default = Some(sidecar);
                    }
                }
            }
        } else if !root_namespace.is_empty() && sidecar.namespace == root_namespace {
            match sidecar.workload_selector.as_ref() {
                Some(selector) if !selector.labels.is_empty() => {
                    // Kubernetes Sidecar selectors in the root namespace remain
                    // namespace-scoped. This tier is primarily for native config
                    // that intentionally omits selector.namespace to opt in to a
                    // mesh-wide workload selector.
                    if workload_selector_matches(selector, workload_namespace, workload_labels)
                        && root_workload_scoped
                            .map(|current| sidecar.name.as_str() < current.name.as_str())
                            .unwrap_or(true)
                    {
                        root_workload_scoped = Some(sidecar);
                    }
                }
                _ => {
                    if root_namespace_default
                        .map(|current| sidecar.name.as_str() < current.name.as_str())
                        .unwrap_or(true)
                    {
                        root_namespace_default = Some(sidecar);
                    }
                }
            }
        }
    }

    let selected = workload_scoped
        .or(root_workload_scoped)
        .or(namespace_default)
        .or(root_namespace_default)?;
    if selected.egress_inherits_defaults {
        if let Some(namespace_default) = namespace_default {
            // Namespace defaults retain precedence over root defaults. When
            // the namespace default inherits and a root default exists, keep
            // walking the inheritance chain rather than failing open.
            if !std::ptr::eq(selected, namespace_default)
                && !namespace_default.egress_inherits_defaults
            {
                return Some(ResolvedSidecarEgress {
                    namespace: sidecar_host_match_namespace(
                        namespace_default,
                        workload_namespace,
                        root_namespace,
                    ),
                    egress: &namespace_default.egress,
                });
            }
            if namespace_default.egress_inherits_defaults {
                if let Some(root_namespace_default) = root_namespace_default
                    && !root_namespace_default.egress_inherits_defaults
                {
                    return Some(ResolvedSidecarEgress {
                        namespace: sidecar_host_match_namespace(
                            root_namespace_default,
                            workload_namespace,
                            root_namespace,
                        ),
                        egress: &root_namespace_default.egress,
                    });
                }
                return None;
            }
        }
        if let Some(root_namespace_default) = root_namespace_default
            && !std::ptr::eq(selected, root_namespace_default)
            && !root_namespace_default.egress_inherits_defaults
        {
            return Some(ResolvedSidecarEgress {
                namespace: sidecar_host_match_namespace(
                    root_namespace_default,
                    workload_namespace,
                    root_namespace,
                ),
                egress: &root_namespace_default.egress,
            });
        }
        return None;
    }

    Some(ResolvedSidecarEgress {
        namespace: sidecar_host_match_namespace(selected, workload_namespace, root_namespace),
        egress: &selected.egress,
    })
}

/// Resolve the effective outbound traffic policy for a workload slice.
///
/// Precedence (exact):
/// 1. Applicable Sidecar's `outbound_traffic_policy` when set — selected with
///    the same tiers as egress/ingress (`select_applicable_sidecar`), without
///    walking the egress `inherits_defaults` chain.
/// 2. Else `MeshConfig.outbound_traffic_policy` (mesh-wide / native CRD).
/// 3. Else `None` — materialization falls back to
///    `FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY` / runtime `AllowAny`.
///
/// Always resolved (independent of `FERRUM_MESH_SIDECAR_ENFORCED`): Sidecar
/// egress host narrowing stays gated, but `outboundTrafficPolicy` is a
/// security control that must apply once translated, matching mesh-wide
/// `outbound_traffic_policy` which already applies without the Sidecar flag.
fn resolve_effective_outbound_traffic_policy<L: WorkloadLabels + ?Sized>(
    mesh: &MeshConfig,
    workload_namespace: &str,
    workload_labels: &L,
) -> Option<OutboundTrafficPolicy> {
    if let Some(sidecar) = select_applicable_sidecar(
        &mesh.sidecars,
        workload_namespace,
        workload_labels,
        mesh.istio_root_namespace.as_str(),
    ) && let Some(policy) = sidecar.outbound_traffic_policy
    {
        return Some(policy);
    }
    mesh.outbound_traffic_policy
}

/// Select the single applicable `Sidecar` for a workload by the SAME tier
/// precedence the egress resolver uses (workload-scoped → root workload-scoped
/// → namespace default → root-namespace default), with the ASCII-smallest
/// `name` tiebreak within a tier. Unlike [`resolve_applicable_sidecar_egress`],
/// this does NOT walk the egress `inherits_defaults` chain: that walk only
/// redirects which Sidecar's *egress scope* applies, while *ingress* listeners
/// are always taken from the selected Sidecar's own `ingress[]` (an omitted
/// `ingress` simply means "no custom listeners").
fn select_applicable_sidecar<'a, L: WorkloadLabels + ?Sized>(
    sidecars: &'a [MeshSidecar],
    workload_namespace: &str,
    workload_labels: &L,
    istio_root_namespace: &str,
) -> Option<&'a MeshSidecar> {
    let mut workload_scoped: Option<&MeshSidecar> = None;
    let mut root_workload_scoped: Option<&MeshSidecar> = None;
    let mut namespace_default: Option<&MeshSidecar> = None;
    let mut root_namespace_default: Option<&MeshSidecar> = None;
    let root_namespace = istio_root_namespace.trim();

    let smaller = |candidate: &MeshSidecar, current: Option<&MeshSidecar>| {
        current
            .map(|c| candidate.name.as_str() < c.name.as_str())
            .unwrap_or(true)
    };

    for sidecar in sidecars {
        if sidecar.namespace == workload_namespace {
            match sidecar.workload_selector.as_ref() {
                Some(selector) if !selector.labels.is_empty() => {
                    if workload_selector_matches(selector, workload_namespace, workload_labels)
                        && smaller(sidecar, workload_scoped)
                    {
                        workload_scoped = Some(sidecar);
                    }
                }
                _ => {
                    if smaller(sidecar, namespace_default) {
                        namespace_default = Some(sidecar);
                    }
                }
            }
        } else if !root_namespace.is_empty() && sidecar.namespace == root_namespace {
            match sidecar.workload_selector.as_ref() {
                Some(selector) if !selector.labels.is_empty() => {
                    if workload_selector_matches(selector, workload_namespace, workload_labels)
                        && smaller(sidecar, root_workload_scoped)
                    {
                        root_workload_scoped = Some(sidecar);
                    }
                }
                _ => {
                    if smaller(sidecar, root_namespace_default) {
                        root_namespace_default = Some(sidecar);
                    }
                }
            }
        }
    }

    workload_scoped
        .or(root_workload_scoped)
        .or(namespace_default)
        .or(root_namespace_default)
}

/// Resolve the routable custom inbound listeners from a workload's applicable
/// `Sidecar.ingress[]`, returning `(resolved_listeners, ingress_declared,
/// declared_http_ports)`.
///
/// Unsupported entries (Unix-socket / non-loopback `defaultEndpoint`,
/// non-HTTP-family protocol, zero port) are dropped fail-closed and warned; only
/// the entries that resolve to a loopback host:port HTTP route are returned.
///
/// `ingress_declared` is `true` when the applicable Sidecar DECLARED an
/// `ingress` block — a non-empty `ingress[]` OR an explicit empty `ingress: []`
/// (Istio distinguishes a declared-empty list from an omitted block) —
/// independent of whether any entry resolved. This is the fail-closed marker the
/// inbound materializer needs: an operator that declares ingress (even one whose
/// entries are ALL unsupported, or an explicit empty list) has explicitly opted
/// out of the default per-service-port inbound listeners (Istio's `ingress`
/// REPLACES them), so the materializer must SKIP the default routes rather than
/// silently exposing them when the resolved list is empty. (Resolved listeners
/// can be empty while declared is true; declared can never be false while
/// resolved is non-empty.)
///
/// `declared_http_ports` is the count of DISTINCT HTTP-family listener ports the
/// Sidecar declared (`MeshSidecarIngress::is_declared_http_family_listener`),
/// whether or not each one's `defaultEndpoint` resolved — so it can EXCEED
/// `resolved_listeners.len()` when an HTTP-family entry has an omitted / `unix://`
/// / off-box endpoint. The router uses it as the ingress group's
/// `declared_http_ports` so a partially materialized group stays ambiguous to an
/// orig-dst-less request (F6 §6.2): without it, two declared listeners with one
/// resolved would collapse to a single-listener no-signal pass-through and route
/// the skipped port's traffic to the surviving sibling. Deduped by port to match
/// the resolved-set dedup below.
fn resolve_applicable_sidecar_ingress<L: WorkloadLabels + ?Sized>(
    sidecars: &[MeshSidecar],
    workload_namespace: &str,
    workload_labels: &L,
    istio_root_namespace: &str,
) -> (Vec<ResolvedIngressListener>, bool, usize) {
    let Some(sidecar) = select_applicable_sidecar(
        sidecars,
        workload_namespace,
        workload_labels,
        istio_root_namespace,
    ) else {
        return (Vec::new(), false, 0);
    };
    // Per Istio, declaring `ingress[]` REPLACES the default per-service-port
    // inbound listeners — and Istio distinguishes an OMITTED ingress block (keep
    // defaults) from a DECLARED one, INCLUDING an explicit empty `ingress: []`
    // (no custom listeners, but defaults still suppressed). `ingress_declared`
    // (set by the K8s translator on `spec.ingress` PRESENCE; defaults false on
    // the native path) carries the explicit-empty case; a non-empty `ingress`
    // always declares regardless. Folding both keeps the fail-closed marker
    // correct for K8s explicit-`[]`, native non-empty, and native explicit-empty
    // (operator sets `ingress_declared: true` with an empty list).
    let ingress_declared = sidecar.ingress_declared || !sidecar.ingress.is_empty();
    // Distinct HTTP-family listener ports the operator declared, counted BEFORE
    // endpoint resolution so an HTTP-family entry whose `defaultEndpoint` is
    // omitted / `unix://` / off-box still contributes its port. Deduped by port,
    // mirroring `seen_ports` for the resolved set, so the count is over distinct
    // ports (two entries on the same port count once, like the resolver keeps the
    // first). Drives the router's fail-closed ingress port ambiguity (F6 §6.2).
    let declared_http_ports = sidecar
        .ingress
        .iter()
        .filter(|entry| entry.is_declared_http_family_listener())
        .map(|entry| entry.port)
        .collect::<BTreeSet<u16>>()
        .len();
    let mut resolved: Vec<ResolvedIngressListener> = Vec::new();
    let mut seen_ports: BTreeSet<u16> = BTreeSet::new();
    for entry in &sidecar.ingress {
        match entry.resolve() {
            Ok(listener) => {
                // Two ingress entries declaring the same listener port is a
                // config error in the resource; keep the first deterministically
                // and warn rather than emitting colliding routes.
                if seen_ports.insert(listener.port) {
                    resolved.push(listener);
                } else {
                    warn!(
                        sidecar = %sidecar.name,
                        namespace = %sidecar.namespace,
                        port = listener.port,
                        "Duplicate Sidecar ingress[] listener port; keeping the first entry"
                    );
                }
            }
            Err(reason) => {
                warn!(
                    sidecar = %sidecar.name,
                    namespace = %sidecar.namespace,
                    port = entry.port,
                    default_endpoint = %entry.default_endpoint,
                    reason = ?reason,
                    "Skipping unsupported Sidecar ingress[] listener (kept in deferred_fields)"
                );
            }
        }
    }
    (resolved, ingress_declared, declared_http_ports)
}

fn sidecar_host_match_namespace<'a>(
    sidecar: &'a MeshSidecar,
    workload_namespace: &'a str,
    root_namespace: &str,
) -> &'a str {
    if !root_namespace.is_empty()
        && sidecar.namespace == root_namespace
        && sidecar.namespace != workload_namespace
    {
        // Root-namespace defaults expand `./*` against the workload's namespace, not the root namespace.
        workload_namespace
    } else {
        sidecar.namespace.as_str()
    }
}

#[derive(Debug, Clone, Copy)]
struct ResolvedSidecarEgress<'a> {
    namespace: &'a str,
    egress: &'a [MeshSidecarEgress],
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SidecarPortAdmission {
    All,
    Ports(BTreeSet<u16>),
}

/// Whether `workload` is one of this sidecar's own local pods. Shared by the
/// slice builder (to capture un-narrowed local inbound services) and the inbound
/// route materializer so the two cannot diverge. A SPIFFE id alone is a
/// service-account identity, not pod-unique, so when the sidecar's labels are
/// known also require a **non-vacuous** selector-label match (an empty selector
/// matches "any" and would reintroduce a shared-service-account leak). Remote
/// multi-cluster endpoints (tagged with a foreign `cluster`) are never local.
pub(crate) fn workload_is_local(
    workload: &Workload,
    local_spiffe: &str,
    sidecar_labels: &BTreeMap<String, String>,
    local_cluster: Option<&str>,
) -> bool {
    if workload.spiffe_id.as_str() != local_spiffe {
        return false;
    }
    if let Some(wc) = workload.cluster.as_deref()
        && local_cluster != Some(wc)
    {
        return false;
    }
    if sidecar_labels.is_empty() {
        return true;
    }
    !workload.selector.labels.is_empty()
        && workload
            .selector
            .labels
            .iter()
            .all(|(k, v)| sidecar_labels.get(k) == Some(v))
}

/// The local workload(s) backing this sidecar, identified precisely — or an
/// empty vec when the identity is **ambiguous**. Shared by the slice builder
/// and the inbound route materializer so the two cannot diverge.
///
/// A SPIFFE id is a service-account identity, not pod-unique, and labels aren't
/// necessarily pod-unique either. So after matching by SPIFFE + labels + cluster
/// (`workload_is_local`), if the matched set still backs **more than one distinct
/// service** we cannot tell which one the local pod serves and return empty
/// rather than materialize inbound routes to the wrong loopback app. A single
/// backed service (including replicas that share one `service_name`) is
/// unambiguous.
pub(crate) fn resolve_local_workloads<'a>(
    workloads: &'a [Workload],
    local_spiffe: &str,
    sidecar_labels: &BTreeMap<String, String>,
    local_cluster: Option<&str>,
) -> Vec<&'a Workload> {
    let matched: Vec<&Workload> = workloads
        .iter()
        .filter(|w| workload_is_local(w, local_spiffe, sidecar_labels, local_cluster))
        .collect();
    // A single local pod backs exactly ONE service. If the matched set spans more
    // than one distinct service the identity is ambiguous — a shared
    // service-account SPIFFE that the labels (if any) don't disambiguate, since
    // labels aren't necessarily pod-unique either — so fail closed rather than
    // materialize inbound routes to the wrong loopback app. (Replicas of one
    // service share its `service_name` and collapse to a single distinct entry.)
    let distinct_services: BTreeSet<(&str, &str)> = matched
        .iter()
        .map(|w| (w.service_name.as_str(), w.namespace.as_str()))
        .collect();
    if distinct_services.len() > 1 {
        warn!(
            local_spiffe,
            distinct_services = distinct_services.len(),
            "Ambiguous local workload: a shared service-account SPIFFE backs multiple \
             services that the sidecar's labels do not disambiguate; skipping inbound \
             materialization. Set FERRUM_MESH_WORKLOAD_LABELS to uniquely identify the \
             local pod's service."
        );
        return Vec::new();
    }
    matched
}

fn narrow_service_ports(
    service: &MeshService,
    sidecar: ResolvedSidecarEgress<'_>,
    cluster_domain: &str,
) -> Option<MeshService> {
    let host_candidates = mesh_service_host_candidates(service, cluster_domain);
    let host_refs: Vec<&str> = host_candidates.iter().map(String::as_str).collect();
    let resource_ports: Vec<u16> = service.ports.iter().map(|port| port.port).collect();
    let admission = sidecar_egress_port_admission(
        sidecar.namespace,
        sidecar.egress,
        service.namespace.as_str(),
        &host_refs,
        Some(&resource_ports),
    )?;
    Some(match admission {
        SidecarPortAdmission::All => service.clone(),
        SidecarPortAdmission::Ports(admitted_ports) => {
            let ports = service
                .ports
                .iter()
                .filter(|port| admitted_ports.contains(&port.port))
                .cloned()
                .collect::<Vec<_>>();
            if ports.is_empty() {
                return None;
            }
            let protocol_overrides = service
                .protocol_overrides
                .iter()
                .filter(|(port, _)| admitted_ports.contains(port))
                .map(|(port, protocol)| (*port, *protocol))
                .collect();
            MeshService {
                ports,
                protocol_overrides,
                ..service.clone()
            }
        }
    })
}

/// Returns the per-host narrowed `ServiceEntry` projections that satisfy the
/// resolved Sidecar egress scope.
///
/// Hosts that share the same admitted port-set are grouped into a single
/// returned entry; hosts that admit different port-sets produce separate
/// entries that all carry the original entry's `name`. As a result the
/// returned `Vec` MAY contain MULTIPLE entries with the same `name` — this is
/// part of the contract. Downstream code MUST NOT assume one name maps to one
/// entry (e.g. do not key materialization caches solely by `entry.name`).
fn narrow_service_entry_ports(
    entry: &ServiceEntry,
    sidecar: ResolvedSidecarEgress<'_>,
) -> Vec<ServiceEntry> {
    let host_refs: Vec<&str> = entry.hosts.iter().map(String::as_str).collect();
    let resource_ports: Vec<u16> = entry.ports.iter().map(|port| port.port).collect();
    if resource_ports.is_empty() {
        return sidecar_egress_port_admission(
            sidecar.namespace,
            sidecar.egress,
            entry.namespace.as_str(),
            &host_refs,
            Some(&resource_ports),
        )
        .map(|_| vec![entry.clone()])
        .unwrap_or_default();
    }

    let resource_port_set: BTreeSet<u16> = resource_ports.iter().copied().collect();
    let mut hosts_by_ports: BTreeMap<BTreeSet<u16>, Vec<String>> = BTreeMap::new();
    for host in &entry.hosts {
        let admission = sidecar_egress_port_admission(
            sidecar.namespace,
            sidecar.egress,
            entry.namespace.as_str(),
            &[host.as_str()],
            Some(&resource_ports),
        );
        let Some(admitted_ports) = admission.map(|admission| match admission {
            SidecarPortAdmission::All => resource_port_set.clone(),
            SidecarPortAdmission::Ports(ports) => ports,
        }) else {
            continue;
        };
        if !admitted_ports.is_empty() {
            hosts_by_ports
                .entry(admitted_ports)
                .or_default()
                .push(host.clone());
        }
    }

    hosts_by_ports
        .into_iter()
        .filter_map(|(admitted_ports, hosts)| {
            let ports = entry
                .ports
                .iter()
                .filter(|port| admitted_ports.contains(&port.port))
                .cloned()
                .collect::<Vec<_>>();
            (!ports.is_empty()).then(|| ServiceEntry {
                hosts,
                ports,
                ..entry.clone()
            })
        })
        .collect()
}

/// Returns `true` when the Sidecar's egress scope admits a resource whose
/// namespace is `resource_namespace` and whose host candidates are
/// `host_candidates`.
///
/// For host-scoped resources such as `MeshDestinationRule`, `resource_ports`
/// is `None` and any matching host admits the resource. For port-carrying
/// resources, `resource_ports` narrows admission to the union of matching
/// `spec.egress[].port.number` values. Port-carrying multi-host
/// `ServiceEntry` resources call this per host so allowed host-port pairs do
/// not become a Cartesian product.
///
/// An empty `egress` list is treated as "allow nothing" — Istio treats an
/// explicit empty egress list this way. An empty `host_candidates` slice
/// can only come from malformed/native config that carries no hosts, and
/// returns `false`.
fn sidecar_egress_includes_service(
    sidecar_namespace: &str,
    sidecar_egress: &[MeshSidecarEgress],
    resource_namespace: &str,
    host_candidates: &[&str],
    resource_ports: Option<&[u16]>,
) -> bool {
    sidecar_egress_port_admission(
        sidecar_namespace,
        sidecar_egress,
        resource_namespace,
        host_candidates,
        resource_ports,
    )
    .is_some()
}

fn sidecar_egress_port_admission(
    sidecar_namespace: &str,
    sidecar_egress: &[MeshSidecarEgress],
    resource_namespace: &str,
    host_candidates: &[&str],
    resource_ports: Option<&[u16]>,
) -> Option<SidecarPortAdmission> {
    if sidecar_egress.is_empty() {
        // Istio: a Sidecar with no egress entries scopes traffic to nothing.
        return None;
    }
    if host_candidates.is_empty() {
        return None;
    }

    let host_matches = |egress_entry: &MeshSidecarEgress| {
        egress_entry.hosts.iter().any(|raw_pattern| {
            sidecar_host_pattern_matches(
                MeshSidecarEgress::parse_host_pattern(raw_pattern),
                sidecar_namespace,
                resource_namespace,
                host_candidates,
            )
        })
    };

    let Some(resource_ports) = resource_ports else {
        return sidecar_egress
            .iter()
            .any(host_matches)
            .then_some(SidecarPortAdmission::All);
    };

    let resource_port_set: BTreeSet<u16> = resource_ports.iter().copied().collect();
    if resource_port_set.is_empty() {
        return sidecar_egress
            .iter()
            .any(|egress_entry| egress_entry.port.is_none() && host_matches(egress_entry))
            .then_some(SidecarPortAdmission::All);
    }

    // Istio precedence: a port-specific egress entry owns that listener;
    // portless entries only cover ports with no dedicated listener.
    let specific_ports: BTreeSet<u16> = sidecar_egress
        .iter()
        .filter_map(|egress_entry| egress_entry.port)
        .collect();
    let mut admitted_ports = BTreeSet::new();
    for port in &resource_port_set {
        let has_specific_listener = specific_ports.contains(port);
        let admitted = sidecar_egress.iter().any(|egress_entry| {
            let port_applies = if has_specific_listener {
                egress_entry.port == Some(*port)
            } else {
                egress_entry.port.is_none()
            };
            port_applies && host_matches(egress_entry)
        });
        if admitted {
            admitted_ports.insert(*port);
        }
    }

    if admitted_ports.is_empty() {
        None
    } else if admitted_ports == resource_port_set {
        Some(SidecarPortAdmission::All)
    } else {
        Some(SidecarPortAdmission::Ports(admitted_ports))
    }
}

/// Match a parsed [`SidecarHostPattern`] against a resource's namespace and
/// host candidates. Hoisted out of `sidecar_egress_includes_service` so the
/// match arms stay readable.
fn sidecar_host_pattern_matches(
    pattern: SidecarHostPattern<'_>,
    sidecar_namespace: &str,
    resource_namespace: &str,
    host_candidates: &[&str],
) -> bool {
    match pattern {
        SidecarHostPattern::AllowAll => true,
        SidecarHostPattern::AnyNamespaceHost { host } => any_host_matches(host, host_candidates),
        SidecarHostPattern::SameNamespaceHost { host } => {
            resource_namespace == sidecar_namespace && any_host_matches(host, host_candidates)
        }
        SidecarHostPattern::SameNamespaceHostBare { host } => {
            resource_namespace == sidecar_namespace && any_host_matches(host, host_candidates)
        }
        SidecarHostPattern::NamespaceWildcard { namespace } => resource_namespace == namespace,
        SidecarHostPattern::NamespaceHost { namespace, host } => {
            resource_namespace == namespace && any_host_matches(host, host_candidates)
        }
    }
}

/// Match a host pattern (the `<dnsName>` part of an Istio Sidecar scope) against
/// every candidate. Returns `true` if any candidate matches.
///
/// Istio Sidecar `egress.hosts` supports a leading-label wildcard:
///   - `reviews.alpha.svc.cluster.local` matches only that exact FQDN.
///   - `*.foo.com` matches `bar.foo.com` (one label before the suffix) but not
///     `foo.com` nor `a.b.foo.com`. This is the Istio Sidecar and mesh DNS
///     proxy semantic; proxy listener host matching intentionally uses broader
///     DNS suffix wildcard semantics.
///
/// Resource hosts may themselves be wildcards (e.g. a `ServiceEntry.hosts`
/// entry of `*.googleapis.com`). When the pattern is `*` it admits any
/// resource host. When both pattern and candidate are wildcard FQDNs, an exact
/// string compare matches them (the operator declared the same wildcard
/// surface). We deliberately do NOT try to compute wildcard-vs-wildcard
/// overlap — Istio's reference implementation also does not.
fn any_host_matches(pattern: &str, host_candidates: &[&str]) -> bool {
    if pattern == "*" {
        return !host_candidates.is_empty();
    }
    host_candidates
        .iter()
        .any(|candidate| host_matches_pattern(pattern, candidate))
}

/// Returns `true` when `candidate` matches `pattern` under Istio Sidecar
/// scope-host semantics (single-label DNS wildcard, case-sensitive — operators
/// are expected to canonicalise to lowercase upstream, identical to how
/// `ServiceEntry.hosts` and `MeshDestinationRule.host` are already stored).
fn host_matches_pattern(pattern: &str, candidate: &str) -> bool {
    if pattern == candidate {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // `*.foo.com` matches `bar.foo.com` (exactly one extra label) but not
        // `foo.com` itself nor `a.b.foo.com`. This remains the Istio Sidecar
        // scope-host semantic even though proxy listener host matching accepts
        // deeper DNS suffix wildcard matches.
        if candidate == suffix {
            return false;
        }
        if let Some(prefix) = candidate.strip_suffix(suffix) {
            return prefix.ends_with('.')
                && prefix.len() > 1
                && !prefix[..prefix.len() - 1].contains('.');
        }
    }
    false
}

/// Scope tier used for PeerAuthentication precedence ranking.
///
/// Discriminant order is load-bearing: `Ord` derive uses it, and the
/// resolution loop picks the highest-valued tier. Istio semantics:
/// WorkloadSelector > Namespace > MeshWide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PeerAuthScope {
    MeshWide = 0,
    Namespace = 1,
    WorkloadSelector = 2,
}

/// Classify a [`MeshProxyConfig`]'s [`PolicyScope`] into a `u8` tier for
/// precedence ordering. Higher = more specific. Mirrors `PeerAuthScope`'s
/// `WorkloadSelector > Namespace > MeshWide` ordering so `MeshProxyConfig`
/// resolution stays byte-identical to PeerAuthentication semantics.
#[inline]
fn proxy_config_scope_tier(pc: &MeshProxyConfig) -> u8 {
    match pc.scope {
        PolicyScope::MeshWide => 0,
        PolicyScope::Namespace { .. } => 1,
        PolicyScope::WorkloadSelector { .. } => 2,
    }
}

/// Classify a [`PeerAuthentication`] into a scope tier for precedence ordering.
fn classify_peer_auth_scope(pa: &PeerAuthentication) -> PeerAuthScope {
    if let Some(scope) = &pa.scope {
        return match scope {
            PolicyScope::MeshWide => PeerAuthScope::MeshWide,
            PolicyScope::Namespace { .. } => PeerAuthScope::Namespace,
            PolicyScope::WorkloadSelector { .. } if pa.has_workload_selector() => {
                PeerAuthScope::WorkloadSelector
            }
            // Defensive normalization for native/file slices: an empty
            // selector is a namespace default when namespace-constrained and a
            // mesh default when it has no namespace constraint.
            PolicyScope::WorkloadSelector { selector } if selector.namespace.is_none() => {
                PeerAuthScope::MeshWide
            }
            PolicyScope::WorkloadSelector { .. } => PeerAuthScope::Namespace,
        };
    }

    if pa.has_workload_selector() {
        PeerAuthScope::WorkloadSelector
    } else {
        PeerAuthScope::Namespace
    }
}

/// Whether a `WorkloadSelector`-scoped PeerAuthentication's namespace constraint
/// is compatible with `proxy_namespace`. Used by the ambiguous-slice fail-closed
/// resolver to escalate ONLY on label divergence: a selector whose namespace does
/// not match is authoritatively non-applicable (namespace is never ambiguous), so
/// it must not force a more-restrictive mTLS mode for an unrelated namespace.
fn peer_auth_selector_namespace_matches(pa: &PeerAuthentication, proxy_namespace: &str) -> bool {
    let selector_namespace = match &pa.scope {
        Some(PolicyScope::WorkloadSelector { selector }) => selector.namespace.as_deref(),
        _ => pa
            .selector
            .as_ref()
            .and_then(|selector| selector.namespace.as_deref()),
    };
    // A scope-form selector with no explicit selector namespace is mesh-wide for
    // namespace purposes; the legacy `pa.selector` form additionally requires the
    // policy's own namespace to match the workload (Istio scopes a bare selector
    // to the policy namespace).
    match (&pa.scope, selector_namespace) {
        (_, Some(ns)) => ns == proxy_namespace,
        (Some(PolicyScope::WorkloadSelector { .. }), None) => true,
        (Some(_), None) | (None, None) => pa.namespace == proxy_namespace,
    }
}

fn peer_auth_applies_to_workload<L: WorkloadLabels + ?Sized>(
    pa: &PeerAuthentication,
    namespace: &str,
    labels: &L,
) -> bool {
    if let Some(scope) = &pa.scope {
        return scope_applies_to_workload(scope, namespace, labels);
    }

    pa.namespace == namespace
        && pa
            .selector
            .as_ref()
            .is_none_or(|selector| workload_selector_matches(selector, namespace, labels))
}

/// Effective inbound mTLS mode a single PeerAuthentication yields for `port`: a
/// per-port override on a selector-scoped policy takes precedence over the
/// policy's top-level `mtls_mode`. Selector-less namespace/mesh-wide policies
/// ignore `port_overrides`, matching Istio's `portLevelMtls` contract.
fn peer_auth_effective_mode(pa: &PeerAuthentication, port: u16) -> MtlsMode {
    if pa.has_workload_selector() {
        pa.port_overrides
            .get(&port)
            .copied()
            .unwrap_or(pa.mtls_mode)
    } else {
        pa.mtls_mode
    }
}

/// Fail-secure restrictiveness rank used to resolve SAME-tier
/// PeerAuthentication ties: a smaller rank is more secure and wins the tie.
/// PeerAuthentication only ever carries the server-side modes
/// (`Strict` > `Permissive` > `Disable`); the DestinationRule client-side modes
/// are invalid here and are ranked least-preferred so a stray one can never
/// outrank — and thereby downgrade — a trusted `Strict`.
fn peer_auth_mtls_restrictiveness(mode: MtlsMode) -> u8 {
    match mode {
        MtlsMode::Strict => 0,
        MtlsMode::Permissive => 1,
        MtlsMode::Disable => 2,
        MtlsMode::Simple | MtlsMode::Mutual | MtlsMode::IstioMutual => 3,
    }
}

/// Resolve the effective mTLS mode for a given port from a set of
/// PeerAuthentication policies.
///
/// This is the canonical resolution function. The `MeshSlice` convenience
/// method delegates here.
pub fn resolve_effective_mtls_mode<L: WorkloadLabels + ?Sized>(
    peer_auths: &[PeerAuthentication],
    namespace: &str,
    labels: &L,
    port: u16,
) -> MtlsMode {
    resolve_peer_auth_mtls_mode(peer_auths, namespace, labels, |pa| {
        peer_auth_effective_mode(pa, port)
    })
}

fn resolve_peer_auth_mtls_mode<'a, L: WorkloadLabels + ?Sized>(
    peer_auths: &'a [PeerAuthentication],
    namespace: &str,
    labels: &L,
    mode_for: impl Fn(&'a PeerAuthentication) -> MtlsMode,
) -> MtlsMode {
    let mut best: Option<(PeerAuthScope, &PeerAuthentication)> = None;

    for pa in peer_auths {
        if !peer_auth_applies_to_workload(pa, namespace, labels) {
            continue;
        }

        let scope = classify_peer_auth_scope(pa);
        // Higher tier wins (WorkloadSelector > Namespace > MeshWide). Within the
        // SAME tier, two equally-applicable PeerAuthentications are an operator
        // misconfiguration, so resolve the tie FAIL-SECURE: prefer the more-
        // restrictive effective mTLS mode for this port (Strict > Permissive >
        // Disable). This is both deterministic AND a real trust boundary —
        // because the winner is decided by mode, not by the policy's namespace
        // string or name, a tenant-controlled policy cannot downgrade inbound
        // mTLS below a trusted same-tier policy by choosing a low-sorting
        // namespace or policy name (and a customized root namespace that sorts
        // after tenants is equally safe). Only when the effective modes are
        // identical do we fall back to the value-neutral `(namespace, name)`
        // ordering, purely to pick a canonical winner deterministically across
        // pods/reconciles.
        let dominated = best.as_ref().is_none_or(|&(current_scope, current_pa)| {
            use std::cmp::Ordering;
            match scope.cmp(&current_scope) {
                Ordering::Greater => true,
                Ordering::Less => false,
                Ordering::Equal => {
                    let candidate = peer_auth_mtls_restrictiveness(mode_for(pa));
                    let current = peer_auth_mtls_restrictiveness(mode_for(current_pa));
                    match candidate.cmp(&current) {
                        Ordering::Less => true,
                        Ordering::Greater => false,
                        Ordering::Equal => {
                            (pa.namespace.as_str(), pa.name.as_str())
                                < (current_pa.namespace.as_str(), current_pa.name.as_str())
                        }
                    }
                }
            }
        });
        if dominated {
            best = Some((scope, pa));
        }
    }

    match best {
        Some((_, pa)) => mode_for(pa),
        None => MtlsMode::Permissive,
    }
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

fn labels_to_btree(labels: &HashMap<String, String>) -> BTreeMap<String, String> {
    labels
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::GatewayConfig;
    use crate::identity::spiffe::{SpiffeId, TrustDomain};
    use crate::modes::mesh::config::{
        AppProtocol, EastWestGateway, MeshAccessLoggingConfig, MeshConfig, MeshDestinationRule,
        MeshPolicy, MeshProxyConfig, MeshRequestAuthentication, MeshRule, MeshService, MeshSidecar,
        MeshSidecarEgress, MeshSidecarIngress, MeshTelemetryConfig, MeshTelemetryResource,
        MeshWaypointBinding, MeshWaypointServiceRef, MtlsMode, MultiClusterConfig,
        NodeWaypointEndpoint, PeerAuthentication, PolicyAction, PolicyScope, RemoteCluster,
        ServiceEntry, ServiceEntryLocation, ServicePort, TrustBundle, TrustBundleSet, Workload,
        WorkloadPort, WorkloadRef, WorkloadSelector,
    };
    use std::collections::HashMap;

    // ── Helpers ──────────────────────────────────────────────────────────

    fn td() -> TrustDomain {
        TrustDomain::new("test.local").unwrap()
    }

    fn make_workload(namespace: &str, service: &str, labels: HashMap<String, String>) -> Workload {
        let td = td();
        let path = format!("ns/{namespace}/sa/{service}");
        Workload {
            spiffe_id: SpiffeId::from_parts(&td, &path).unwrap(),
            selector: WorkloadSelector {
                labels,
                namespace: Some(namespace.into()),
            },
            service_name: service.into(),
            addresses: vec!["10.0.0.1".into()],
            ports: vec![WorkloadPort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: None,
            }],
            trust_domain: td,
            namespace: namespace.into(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        }
    }

    fn make_node_waypoint_endpoint(spiffe: &str, address: &str) -> NodeWaypointEndpoint {
        NodeWaypointEndpoint {
            address: address.to_string(),
            hbone_port: 15008,
            spiffe_id: SpiffeId::new(spiffe).unwrap(),
            node_name: None,
            node_uid: None,
            network: None,
            cluster: None,
        }
    }

    fn make_service(namespace: &str, name: &str) -> MeshService {
        make_service_with_ports(namespace, name, &[80])
    }

    fn make_service_with_ports(namespace: &str, name: &str, ports: &[u16]) -> MeshService {
        MeshService {
            cluster_ips: Vec::new(),
            name: name.into(),
            namespace: namespace.into(),
            ports: ports
                .iter()
                .map(|port| ServicePort {
                    port: *port,
                    protocol: AppProtocol::Http,
                    name: None,
                    target_port: None,
                })
                .collect(),
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
        }
    }

    fn make_service_with_workload_refs(
        namespace: &str,
        name: &str,
        workload_spiffe_ids: Vec<SpiffeId>,
    ) -> MeshService {
        let mut service = make_service(namespace, name);
        service.workloads = workload_spiffe_ids
            .into_iter()
            .map(|spiffe_id| WorkloadRef { spiffe_id })
            .collect();
        service
    }

    #[test]
    fn service_waypoint_slice_keeps_extension_configs_for_bound_service_namespaces() {
        let mesh = MeshConfig {
            extension_configs: vec![
                MeshExtensionConfig {
                    name: "infra-ext".into(),
                    namespace: "infra".into(),
                    type_url: "type.googleapis.com/test".into(),
                    value: vec![1],
                },
                MeshExtensionConfig {
                    name: "default-ext".into(),
                    namespace: "default".into(),
                    type_url: "type.googleapis.com/test".into(),
                    value: vec![2],
                },
                MeshExtensionConfig {
                    name: "other-ext".into(),
                    namespace: "other".into(),
                    type_url: "type.googleapis.com/test".into(),
                    value: vec![3],
                },
                MeshExtensionConfig {
                    name: "unscoped-ext".into(),
                    namespace: String::new(),
                    type_url: "type.googleapis.com/test".into(),
                    value: vec![4],
                },
            ],
            waypoint_bindings: vec![MeshWaypointBinding {
                name: "waypoint".into(),
                namespace: "infra".into(),
                waypoint_for: "service".into(),
                services: vec![MeshWaypointServiceRef {
                    namespace: "default".into(),
                    name: "reviews".into(),
                }],
            }],
            services: vec![make_service("default", "reviews")],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(
            &config,
            MeshSliceRequest {
                node_id: "node-1".into(),
                namespace: "infra".into(),
                waypoint_name: Some("waypoint".into()),
                ..MeshSliceRequest::default()
            },
        );
        let mut names: Vec<String> = slice
            .extension_configs
            .iter()
            .map(|ext| ext.name.clone())
            .collect();
        names.sort();
        assert_eq!(names, vec!["default-ext", "infra-ext"]);
    }

    #[test]
    fn ambient_udp_slice_keeps_cross_namespace_source_policy_candidates() {
        let mut destination = make_workload(
            "default",
            "reviews",
            HashMap::from([("app".into(), "reviews".into())]),
        );
        destination.pod_uid = Some("6ba7b810-9dad-11d1-80b4-00c04fd430c8".into());
        let destination_id = destination.spiffe_id.clone();
        let mut source = make_workload(
            "clients",
            "client",
            HashMap::from([("app".into(), "client".into())]),
        );
        source.pod_uid = Some("16b2c3d4-9dad-11d1-80b4-00c04fd430c8".into());
        let mesh = MeshConfig {
            workloads: vec![destination, source],
            services: vec![make_service_with_workload_refs(
                "default",
                "reviews",
                vec![destination_id],
            )],
            mesh_policies: vec![make_policy(
                "clients-source-policy",
                "clients",
                PolicyScope::Namespace {
                    namespace: "clients".into(),
                },
            )],
            waypoint_bindings: vec![MeshWaypointBinding {
                name: "waypoint".into(),
                namespace: "infra".into(),
                waypoint_for: "service".into(),
                services: vec![MeshWaypointServiceRef {
                    namespace: "default".into(),
                    name: "reviews".into(),
                }],
            }],
            ..MeshConfig::default()
        };

        let slice = MeshSlice::from_gateway_config(
            &config_with_mesh(mesh),
            MeshSliceRequest {
                node_id: "node-1".into(),
                namespace: "infra".into(),
                waypoint_name: Some("waypoint".into()),
                ambient_udp_source_scoping: true,
                node_waypoint_capture_scoping: false,
                ..MeshSliceRequest::default()
            },
        );

        assert_eq!(slice.workloads.len(), 1);
        assert_eq!(slice.workloads[0].service_name, "reviews");
        assert_eq!(slice.ambient_udp_source_workloads.len(), 2);
        assert!(
            slice
                .ambient_udp_source_workloads
                .iter()
                .any(|workload| workload.service_name == "client"),
            "source scope inventory must survive destination-workload narrowing"
        );
        assert_eq!(slice.mesh_policies.len(), 1);
        assert_eq!(slice.mesh_policies[0].name, "clients-source-policy");
    }

    fn make_policy(name: &str, namespace: &str, scope: PolicyScope) -> MeshPolicy {
        MeshPolicy {
            name: name.into(),
            namespace: namespace.into(),
            scope,
            rules: vec![MeshRule {
                from: Vec::new(),
                to: Vec::new(),
                when: Vec::new(),
                request_principals: Vec::new(),
                not_request_principals: Vec::new(),
                source_negation: Default::default(),
                never_matches: false,
                action: PolicyAction::Allow,
            }],
        }
    }

    fn make_peer_auth(
        name: &str,
        namespace: &str,
        selector: Option<WorkloadSelector>,
    ) -> PeerAuthentication {
        PeerAuthentication {
            name: name.into(),
            namespace: namespace.into(),
            scope: None,
            selector,
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::new(),
        }
    }

    fn make_service_entry(name: &str, namespace: &str, export_to: Vec<String>) -> ServiceEntry {
        ServiceEntry {
            name: name.into(),
            namespace: namespace.into(),
            hosts: vec!["external.example.com".into()],
            endpoints: Vec::new(),
            resolution: crate::modes::mesh::config::Resolution::None,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 443,
                protocol: AppProtocol::Http2,
                name: None,
                target_port: None,
            }],
            export_to,
            workload_selector: None,
        }
    }

    fn make_request_auth(
        name: &str,
        namespace: &str,
        scope: PolicyScope,
    ) -> MeshRequestAuthentication {
        MeshRequestAuthentication {
            name: name.into(),
            namespace: namespace.into(),
            scope,
            jwt_rules: Vec::new(),
        }
    }

    fn make_telemetry(name: &str, namespace: &str, scope: PolicyScope) -> MeshTelemetryResource {
        MeshTelemetryResource {
            name: name.into(),
            namespace: namespace.into(),
            scope,
            config: MeshTelemetryConfig {
                tracing: None,
                metrics: None,
                access_logging: Some(MeshAccessLoggingConfig {
                    enabled: true,
                    filter: None,
                }),
            },
        }
    }

    fn make_trust_bundle_set() -> TrustBundleSet {
        TrustBundleSet {
            local: TrustBundle {
                trust_domain: td(),
                x509_authorities: Vec::new(),
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: Vec::new(),
        }
    }

    fn make_multi_cluster() -> MultiClusterConfig {
        MultiClusterConfig {
            local_cluster: Some("cluster-a".into()),
            federation_endpoint: None,
            remote_clusters: vec![RemoteCluster {
                name: "cluster-b".into(),
                trust_domain: td(),
                network: None,
                control_plane_url: None,
                federation_endpoint: None,
                discovery_credential_ref: None,
            }],
            east_west_gateways: Vec::new(),
        }
    }

    fn slice_request(namespace: &str) -> MeshSliceRequest {
        MeshSliceRequest {
            node_id: "node-1".into(),
            namespace: namespace.into(),
            workload_spiffe_id: None,
            waypoint_name: None,
            labels: BTreeMap::new(),
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            enforce_sidecar_egress: false,
            sidecar_egress_dry_run: false,
            enforce_sidecar_identity_narrowing: false,
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
        }
    }

    fn slice_request_with_labels(
        namespace: &str,
        labels: BTreeMap<String, String>,
    ) -> MeshSliceRequest {
        MeshSliceRequest {
            node_id: "node-1".into(),
            namespace: namespace.into(),
            workload_spiffe_id: None,
            waypoint_name: None,
            labels,
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            enforce_sidecar_egress: false,
            sidecar_egress_dry_run: false,
            enforce_sidecar_identity_narrowing: false,
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
        }
    }

    fn config_with_mesh(mesh: MeshConfig) -> GatewayConfig {
        GatewayConfig {
            mesh: Some(Box::new(mesh)),
            ..GatewayConfig::default()
        }
    }

    // ── content_eq tests ────────────────────────────────────────────────

    #[test]
    fn content_eq_identical_slices() {
        let slice = MeshSlice {
            node_id: "n1".into(),
            namespace: "ns".into(),
            workload_spiffe_id: Some("spiffe://td/ns/x/sa/y".into()),
            labels: BTreeMap::from([("app".into(), "web".into())]),
            labels_ambiguous: false,
            version: "v1".into(),
            revision: None,
            workloads: vec![make_workload("ns", "web", HashMap::new())],
            ambient_udp_source_workloads: Vec::new(),
            node_waypoint_assertors: Vec::new(),
            node_waypoint_capture_destinations: Vec::new(),
            node_waypoint_capture_peer_authentications: Vec::new(),
            services: vec![make_service("ns", "web")],
            local_inbound_services: Vec::new(),
            local_inbound_workloads: None,
            local_ingress_listeners: Vec::new(),
            sidecar_ingress_declared: false,
            declared_ingress_http_ports: 0,
            mesh_policies: vec![make_policy("p1", "ns", PolicyScope::MeshWide)],
            peer_authentications: vec![make_peer_auth("pa1", "ns", None)],
            service_entries: vec![make_service_entry("se1", "ns", vec!["*".into()])],
            destination_rules: Vec::new(),
            virtual_service_cors_policies: Vec::new(),
            proxy_configs: Vec::new(),
            request_authentications: vec![make_request_auth("ra1", "ns", PolicyScope::MeshWide)],
            telemetry_resources: vec![make_telemetry("t1", "ns", PolicyScope::MeshWide)],
            trust_bundles: Some(make_trust_bundle_set()),
            multi_cluster: Some(make_multi_cluster()),
            outbound_traffic_policy: None,
            sidecar_egress_scope: None,
            extension_configs: Vec::new(),
            runtime_overlay: MeshRuntimeOverlay::default(),
            waypoint_name: None,
        };
        assert!(slice.content_eq(&slice.clone()));
    }

    #[test]
    fn content_eq_ignores_version_difference() {
        let mut a = MeshSlice {
            node_id: "n1".into(),
            namespace: "ns".into(),
            version: "2024-01-01T00:00:00Z".into(),
            workloads: vec![make_workload("ns", "api", HashMap::new())],
            ..MeshSlice::default()
        };
        let mut b = a.clone();
        b.version = "2024-06-15T12:00:00Z".into();
        assert!(a.content_eq(&b), "version difference should be ignored");

        // Verify PartialEq does NOT ignore version (sanity check).
        assert_ne!(a, b);

        // Both empty versions also equal.
        a.version = String::new();
        b.version = String::new();
        assert!(a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_workloads_change() {
        let a = MeshSlice {
            workloads: vec![make_workload("ns", "api", HashMap::new())],
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_ambient_udp_source_workloads_change() {
        let a = MeshSlice {
            ambient_udp_source_workloads: vec![make_workload("ns", "client", HashMap::new())],
            ..MeshSlice::default()
        };
        assert!(!a.content_eq(&MeshSlice::default()));
    }

    #[test]
    fn content_eq_detects_services_change() {
        let a = MeshSlice {
            services: vec![make_service("ns", "svc")],
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_sidecar_ingress_declared_change() {
        // Codex round-2 P1: the all-unsupported-ingress scenario. A workload
        // changes from "no ingress[]" to an ingress[] whose entries are ALL
        // unsupported (or have no local-service anchor): `local_ingress_listeners`
        // stays empty BUT `sidecar_ingress_declared` flips false→true. If
        // `content_eq` ignored the marker, MeshSubscribe/update dedupe would treat
        // the slices as unchanged and keep serving the now-stale default inbound
        // routes the operator replaced. The marker must be compared.
        let a = MeshSlice {
            sidecar_ingress_declared: true,
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(
            !a.content_eq(&b),
            "a flipped sidecar_ingress_declared marker (empty listeners) must be a content change"
        );
        // Symmetric, and identical marker values are equal.
        assert!(!b.content_eq(&a));
        assert!(a.content_eq(&a.clone()));
    }

    #[test]
    fn content_eq_detects_labels_ambiguous_change() {
        // The ambiguous-labels marker can flip while `labels` is unchanged (the
        // shared-SPIFFE candidate set changes but the intersection does not),
        // altering how the xDS DP resolves label precedence. It must count as a
        // content change so the slice is re-broadcast and the DP updates.
        let a = MeshSlice {
            labels_ambiguous: true,
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(
            !a.content_eq(&b),
            "a flipped labels_ambiguous marker must be a content change"
        );
        assert!(!b.content_eq(&a));
        assert!(a.content_eq(&a.clone()));
    }

    fn selector_peer_auth(
        name: &str,
        key: &str,
        value: &str,
        mode: MtlsMode,
    ) -> PeerAuthentication {
        PeerAuthentication {
            name: name.into(),
            namespace: "default".into(),
            scope: None,
            selector: Some(WorkloadSelector {
                labels: HashMap::from([(key.to_string(), value.to_string())]),
                namespace: None,
            }),
            mtls_mode: mode,
            port_overrides: HashMap::new(),
        }
    }

    #[test]
    fn fail_closed_mtls_escalates_unresolvable_selector_strict_on_ambiguous_slice() {
        // Codex P1: an ambiguous shared-SPIFFE slice carries a candidate-only
        // STRICT PeerAuthentication keyed on the divergent `role=api` as a
        // superset, but `labels` is only the partial intersection `app=shared`,
        // which does NOT match the selector. The plain resolver drops it and
        // falls back to Permissive — a fail-OPEN. The fail-closed resolver must
        // escalate to STRICT because it cannot prove the selector does not apply.
        let slice = MeshSlice {
            namespace: "default".into(),
            labels: BTreeMap::from([("app".to_string(), "shared".to_string())]),
            labels_ambiguous: true,
            peer_authentications: vec![selector_peer_auth(
                "role-api-strict",
                "role",
                "api",
                MtlsMode::Strict,
            )],
            ..MeshSlice::default()
        };
        assert_eq!(
            slice.resolve_effective_mtls_mode(8080),
            MtlsMode::Permissive,
            "the plain resolver drops the unresolvable selector (the fail-open this fix closes)"
        );
        assert_eq!(
            slice.resolve_inbound_mtls_mode_fail_closed(8080),
            MtlsMode::Strict,
            "the fail-closed resolver must escalate to STRICT for an unresolvable candidate STRICT"
        );
    }

    #[test]
    fn fail_closed_mtls_is_enforcement_identical_on_non_ambiguous_slice() {
        // Guardrail: the non-ambiguous case must be byte-identical to the plain
        // resolver. Same slice as above but NOT flagged ambiguous (the labels are
        // authoritative), so the selector simply does not apply and Permissive is
        // correct — no escalation.
        let slice = MeshSlice {
            namespace: "default".into(),
            labels: BTreeMap::from([("app".to_string(), "shared".to_string())]),
            labels_ambiguous: false,
            peer_authentications: vec![selector_peer_auth(
                "role-api-strict",
                "role",
                "api",
                MtlsMode::Strict,
            )],
            ..MeshSlice::default()
        };
        assert_eq!(
            slice.resolve_effective_mtls_mode(8080),
            slice.resolve_inbound_mtls_mode_fail_closed(8080),
            "fail-closed resolution must equal plain resolution on a non-ambiguous slice"
        );
        assert_eq!(
            slice.resolve_inbound_mtls_mode_fail_closed(8080),
            MtlsMode::Permissive,
        );
    }

    #[test]
    fn fail_closed_mtls_does_not_escalate_when_selector_resolved_by_intersection() {
        // The candidate-only selector IS satisfied by the partial intersection
        // (`app=shared` selector against `app=shared` labels), so the plain
        // resolver already enforces STRICT and the fail-closed path is a no-op —
        // no over-escalation beyond what actually resolved.
        let slice = MeshSlice {
            namespace: "default".into(),
            labels: BTreeMap::from([("app".to_string(), "shared".to_string())]),
            labels_ambiguous: true,
            peer_authentications: vec![selector_peer_auth(
                "app-shared-strict",
                "app",
                "shared",
                MtlsMode::Strict,
            )],
            ..MeshSlice::default()
        };
        assert_eq!(slice.resolve_effective_mtls_mode(8080), MtlsMode::Strict,);
        assert_eq!(
            slice.resolve_inbound_mtls_mode_fail_closed(8080),
            MtlsMode::Strict,
        );
    }

    #[test]
    fn fail_closed_mtls_does_not_escalate_unresolvable_permissive_selector() {
        // An ambiguous slice whose only unresolvable candidate-only selector is
        // PERMISSIVE (not STRICT) must NOT escalate past Permissive — the
        // fail-closed path escalates only toward the MORE restrictive mode, it
        // does not invent STRICT where no STRICT policy exists.
        let slice = MeshSlice {
            namespace: "default".into(),
            labels: BTreeMap::from([("app".to_string(), "shared".to_string())]),
            labels_ambiguous: true,
            peer_authentications: vec![selector_peer_auth(
                "role-api-permissive",
                "role",
                "api",
                MtlsMode::Permissive,
            )],
            ..MeshSlice::default()
        };
        assert_eq!(
            slice.resolve_inbound_mtls_mode_fail_closed(8080),
            MtlsMode::Permissive,
            "no STRICT candidate exists, so fail-closed resolution stays Permissive"
        );
    }

    #[test]
    fn fail_closed_mtls_does_not_escalate_selector_in_other_namespace() {
        // A candidate-only STRICT PeerAuth whose selector targets a DIFFERENT
        // namespace must NOT escalate: namespace is authoritative (never
        // ambiguous), so the policy genuinely does not apply to this workload.
        // Only LABEL divergence within this namespace is escalated fail-closed.
        let mut pa = selector_peer_auth("other-ns-strict", "role", "api", MtlsMode::Strict);
        pa.selector = Some(WorkloadSelector {
            labels: HashMap::from([("role".to_string(), "api".to_string())]),
            namespace: Some("other-namespace".to_string()),
        });
        let slice = MeshSlice {
            namespace: "default".into(),
            labels: BTreeMap::from([("app".to_string(), "shared".to_string())]),
            labels_ambiguous: true,
            peer_authentications: vec![pa],
            ..MeshSlice::default()
        };
        assert_eq!(
            slice.resolve_inbound_mtls_mode_fail_closed(8080),
            MtlsMode::Permissive,
            "a selector in another namespace is authoritatively non-applicable; no escalation"
        );
    }

    #[test]
    fn content_eq_detects_mesh_policies_change() {
        let a = MeshSlice {
            mesh_policies: vec![make_policy("p", "ns", PolicyScope::MeshWide)],
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_peer_auth_change() {
        let a = MeshSlice {
            peer_authentications: vec![make_peer_auth("pa", "ns", None)],
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_service_entries_change() {
        let a = MeshSlice {
            service_entries: vec![make_service_entry("se", "ns", vec![])],
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_request_auth_change() {
        let a = MeshSlice {
            request_authentications: vec![make_request_auth("ra", "ns", PolicyScope::MeshWide)],
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_telemetry_change() {
        let a = MeshSlice {
            telemetry_resources: vec![make_telemetry("t", "ns", PolicyScope::MeshWide)],
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_trust_bundles_change() {
        let a = MeshSlice {
            trust_bundles: Some(make_trust_bundle_set()),
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_multi_cluster_change() {
        let a = MeshSlice {
            multi_cluster: Some(make_multi_cluster()),
            outbound_traffic_policy: None,
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_node_id_change() {
        let a = MeshSlice {
            node_id: "node-a".into(),
            ..MeshSlice::default()
        };
        let b = MeshSlice {
            node_id: "node-b".into(),
            ..MeshSlice::default()
        };
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_namespace_change() {
        let a = MeshSlice {
            namespace: "ns-a".into(),
            ..MeshSlice::default()
        };
        let b = MeshSlice {
            namespace: "ns-b".into(),
            ..MeshSlice::default()
        };
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_labels_change() {
        let a = MeshSlice {
            labels: BTreeMap::from([("app".into(), "web".into())]),
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_spiffe_id_change() {
        let a = MeshSlice {
            workload_spiffe_id: Some("spiffe://td/ns/x/sa/y".into()),
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_empty_defaults() {
        let a = MeshSlice::default();
        let b = MeshSlice::default();
        assert!(a.content_eq(&b));
    }

    // ── from_gateway_config tests ───────────────────────────────────────

    #[test]
    fn from_gateway_config_no_mesh_returns_empty_slice() {
        let config = GatewayConfig::default();
        let slice = MeshSlice::from_gateway_config(&config, slice_request("default"));
        assert!(slice.workloads.is_empty());
        assert!(slice.services.is_empty());
        assert!(slice.mesh_policies.is_empty());
        assert!(slice.peer_authentications.is_empty());
        assert!(slice.service_entries.is_empty());
        assert!(slice.request_authentications.is_empty());
        assert!(slice.telemetry_resources.is_empty());
        assert!(slice.trust_bundles.is_none());
        assert!(slice.multi_cluster.is_none());
        assert_eq!(slice.node_id, "node-1");
        assert_eq!(slice.namespace, "default");
    }

    #[test]
    fn from_gateway_config_empty_mesh_returns_empty_collections() {
        let config = config_with_mesh(MeshConfig::default());
        let slice = MeshSlice::from_gateway_config(&config, slice_request("ns"));
        assert!(slice.workloads.is_empty());
        assert!(slice.services.is_empty());
        assert!(slice.mesh_policies.is_empty());
    }

    #[test]
    fn from_gateway_config_filters_workloads_by_namespace() {
        let mesh = MeshConfig {
            workloads: vec![
                make_workload("alpha", "svc-a", HashMap::new()),
                make_workload("beta", "svc-b", HashMap::new()),
                make_workload("alpha", "svc-c", HashMap::new()),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.workloads.len(), 2);
        assert!(slice.workloads.iter().all(|w| w.namespace == "alpha"));
    }

    #[test]
    fn from_gateway_config_preserves_workload_node_waypoint_endpoint() {
        let mut workload = make_workload("alpha", "svc-a", HashMap::new());
        workload.node_waypoint = Some(NodeWaypointEndpoint {
            address: "10.2.0.17".into(),
            hbone_port: 16008,
            spiffe_id: SpiffeId::new(
                "spiffe://test.local/ns/ferrum-system/sa/node-waypoint-worker-a",
            )
            .unwrap(),
            node_name: Some("worker-a".into()),
            node_uid: Some("node-uid-a".into()),
            network: Some("network-a".into()),
            cluster: Some("cluster-a".into()),
        });
        let config = config_with_mesh(MeshConfig {
            workloads: vec![workload],
            ..MeshConfig::default()
        });

        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));

        let endpoint = slice.workloads[0]
            .node_waypoint
            .as_ref()
            .expect("node waypoint endpoint survives projection");
        assert_eq!(endpoint.address, "10.2.0.17");
        assert_eq!(endpoint.hbone_port, 16008);
        assert_eq!(
            endpoint.spiffe_id.as_str(),
            "spiffe://test.local/ns/ferrum-system/sa/node-waypoint-worker-a"
        );
        assert_eq!(endpoint.node_name.as_deref(), Some("worker-a"));
        assert_eq!(endpoint.node_uid.as_deref(), Some("node-uid-a"));
        assert_eq!(endpoint.network.as_deref(), Some("network-a"));
        assert_eq!(endpoint.cluster.as_deref(), Some("cluster-a"));
    }

    #[test]
    fn from_gateway_config_node_waypoint_assertors_are_not_namespace_scoped() {
        let waypoint_alpha = "spiffe://test.local/ns/ferrum-system/sa/node-waypoint-alpha";
        let waypoint_beta = "spiffe://test.local/ns/ferrum-system/sa/node-waypoint-beta";
        let mut alpha = make_workload("alpha", "client", HashMap::new());
        alpha.node_waypoint = Some(make_node_waypoint_endpoint(waypoint_alpha, "10.2.0.11"));
        let mut beta = make_workload("beta", "reviews", HashMap::new());
        beta.node_waypoint = Some(make_node_waypoint_endpoint(waypoint_beta, "10.2.0.12"));
        let mut beta_duplicate = make_workload("beta", "ratings", HashMap::new());
        beta_duplicate.node_waypoint = beta.node_waypoint.clone();
        let config = config_with_mesh(MeshConfig {
            workloads: vec![alpha, beta, beta_duplicate],
            ..MeshConfig::default()
        });

        let slice = MeshSlice::from_gateway_config(&config, slice_request("beta"));

        assert!(
            slice
                .workloads
                .iter()
                .all(|workload| workload.namespace == "beta"),
            "visible workloads remain namespace-scoped"
        );
        assert_eq!(
            slice
                .node_waypoint_assertors
                .iter()
                .map(SpiffeId::as_str)
                .collect::<Vec<_>>(),
            vec![waypoint_alpha, waypoint_beta],
            "NodeWaypoint assertor inventory must include source-node assertors outside the destination namespace"
        );
    }

    #[test]
    fn from_gateway_config_filters_services_by_namespace() {
        let mesh = MeshConfig {
            services: vec![
                make_service("alpha", "svc-a"),
                make_service("beta", "svc-b"),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.services.len(), 1);
        assert_eq!(slice.services[0].name, "svc-a");
    }

    #[test]
    fn from_gateway_config_policy_mesh_wide_included_for_any_namespace() {
        let mesh = MeshConfig {
            mesh_policies: vec![make_policy("global", "alpha", PolicyScope::MeshWide)],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.mesh_policies.len(), 1);
        assert_eq!(slice.mesh_policies[0].name, "global");
    }

    #[test]
    fn from_gateway_config_policy_mesh_wide_included_when_policy_namespace_differs() {
        let mesh = MeshConfig {
            mesh_policies: vec![make_policy("global", "other-ns", PolicyScope::MeshWide)],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.mesh_policies.len(), 1);
        assert_eq!(slice.mesh_policies[0].name, "global");
    }

    #[test]
    fn from_gateway_config_policy_namespace_scope_matching() {
        let mesh = MeshConfig {
            mesh_policies: vec![
                make_policy(
                    "ns-match",
                    "alpha",
                    PolicyScope::Namespace {
                        namespace: "alpha".into(),
                    },
                ),
                make_policy(
                    "ns-nomatch",
                    "alpha",
                    PolicyScope::Namespace {
                        namespace: "beta".into(),
                    },
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.mesh_policies.len(), 1);
        assert_eq!(slice.mesh_policies[0].name, "ns-match");
    }

    #[test]
    fn from_gateway_config_policy_workload_selector_with_labels() {
        let labels = BTreeMap::from([("app".into(), "web".into()), ("env".into(), "prod".into())]);
        let mesh = MeshConfig {
            mesh_policies: vec![
                make_policy(
                    "match-labels",
                    "alpha",
                    PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".into(), "web".into())]),
                            namespace: None,
                        },
                    },
                ),
                make_policy(
                    "nomatch-labels",
                    "alpha",
                    PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".into(), "backend".into())]),
                            namespace: None,
                        },
                    },
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice =
            MeshSlice::from_gateway_config(&config, slice_request_with_labels("alpha", labels));
        assert_eq!(slice.mesh_policies.len(), 1);
        assert_eq!(slice.mesh_policies[0].name, "match-labels");
    }

    #[test]
    fn from_gateway_config_policy_workload_selector_empty_labels_matches_all() {
        let mesh = MeshConfig {
            mesh_policies: vec![make_policy(
                "empty-selector",
                "alpha",
                PolicyScope::WorkloadSelector {
                    selector: WorkloadSelector {
                        labels: HashMap::new(),
                        namespace: None,
                    },
                },
            )],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.mesh_policies.len(), 1);
    }

    #[test]
    fn from_gateway_config_peer_auth_filtered_by_namespace() {
        let mesh = MeshConfig {
            peer_authentications: vec![
                make_peer_auth("pa-alpha", "alpha", None),
                make_peer_auth("pa-beta", "beta", None),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.peer_authentications.len(), 1);
        assert_eq!(slice.peer_authentications[0].name, "pa-alpha");
    }

    #[test]
    fn from_gateway_config_peer_auth_with_selector_filters_on_labels() {
        let labels = BTreeMap::from([("tier".into(), "frontend".into())]);
        let mesh = MeshConfig {
            peer_authentications: vec![
                make_peer_auth(
                    "match",
                    "alpha",
                    Some(WorkloadSelector {
                        labels: HashMap::from([("tier".into(), "frontend".into())]),
                        namespace: None,
                    }),
                ),
                make_peer_auth(
                    "nomatch",
                    "alpha",
                    Some(WorkloadSelector {
                        labels: HashMap::from([("tier".into(), "backend".into())]),
                        namespace: None,
                    }),
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice =
            MeshSlice::from_gateway_config(&config, slice_request_with_labels("alpha", labels));
        assert_eq!(slice.peer_authentications.len(), 1);
        assert_eq!(slice.peer_authentications[0].name, "match");
    }

    #[test]
    fn from_gateway_config_peer_auth_no_selector_always_included() {
        let mesh = MeshConfig {
            peer_authentications: vec![make_peer_auth("global-pa", "ns", None)],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("ns"));
        assert_eq!(slice.peer_authentications.len(), 1);
    }

    #[test]
    fn from_gateway_config_service_entry_export_to_star() {
        let mesh = MeshConfig {
            service_entries: vec![make_service_entry("se", "infra", vec!["*".into()])],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("app"));
        assert_eq!(slice.service_entries.len(), 1);
    }

    #[test]
    fn from_gateway_config_service_entry_export_to_specific_namespace() {
        let mesh = MeshConfig {
            service_entries: vec![
                make_service_entry("se-match", "infra", vec!["app".into()]),
                make_service_entry("se-nomatch", "infra", vec!["other".into()]),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("app"));
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "se-match");
    }

    #[test]
    fn from_gateway_config_service_entry_export_to_dot_means_same_namespace() {
        let mesh = MeshConfig {
            service_entries: vec![
                make_service_entry("se-same", "alpha", vec![".".into()]),
                make_service_entry("se-other", "beta", vec![".".into()]),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "se-same");
    }

    #[test]
    fn from_gateway_config_service_entry_empty_export_to_is_namespace_local() {
        let mesh = MeshConfig {
            service_entries: vec![
                make_service_entry("se-local", "alpha", vec![]),
                make_service_entry("se-other", "beta", vec![]),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "se-local");
    }

    #[test]
    fn from_gateway_config_request_auth_mesh_wide_included() {
        let mesh = MeshConfig {
            request_authentications: vec![make_request_auth(
                "ra-global",
                "ns",
                PolicyScope::MeshWide,
            )],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("ns"));
        assert_eq!(slice.request_authentications.len(), 1);
    }

    #[test]
    fn from_gateway_config_request_auth_namespace_scope() {
        let mesh = MeshConfig {
            request_authentications: vec![
                make_request_auth(
                    "ra-match",
                    "ns",
                    PolicyScope::Namespace {
                        namespace: "alpha".into(),
                    },
                ),
                make_request_auth(
                    "ra-nomatch",
                    "ns",
                    PolicyScope::Namespace {
                        namespace: "beta".into(),
                    },
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.request_authentications.len(), 1);
        assert_eq!(slice.request_authentications[0].name, "ra-match");
    }

    #[test]
    fn from_gateway_config_request_auth_workload_selector() {
        let labels = BTreeMap::from([("role".into(), "gateway".into())]);
        let mesh = MeshConfig {
            request_authentications: vec![
                make_request_auth(
                    "ra-selector-match",
                    "ns",
                    PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("role".into(), "gateway".into())]),
                            namespace: None,
                        },
                    },
                ),
                make_request_auth(
                    "ra-selector-nomatch",
                    "ns",
                    PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("role".into(), "worker".into())]),
                            namespace: None,
                        },
                    },
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice =
            MeshSlice::from_gateway_config(&config, slice_request_with_labels("alpha", labels));
        assert_eq!(slice.request_authentications.len(), 1);
        assert_eq!(slice.request_authentications[0].name, "ra-selector-match");
    }

    #[test]
    fn from_gateway_config_telemetry_mesh_wide_included() {
        let mesh = MeshConfig {
            telemetry_resources: vec![make_telemetry("tel", "ns", PolicyScope::MeshWide)],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("ns"));
        assert_eq!(slice.telemetry_resources.len(), 1);
    }

    #[test]
    fn from_gateway_config_telemetry_namespace_scope() {
        let mesh = MeshConfig {
            telemetry_resources: vec![
                make_telemetry(
                    "tel-match",
                    "ns",
                    PolicyScope::Namespace {
                        namespace: "alpha".into(),
                    },
                ),
                make_telemetry(
                    "tel-nomatch",
                    "ns",
                    PolicyScope::Namespace {
                        namespace: "beta".into(),
                    },
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.telemetry_resources.len(), 1);
        assert_eq!(slice.telemetry_resources[0].name, "tel-match");
    }

    #[test]
    fn from_gateway_config_telemetry_workload_selector() {
        let labels = BTreeMap::from([("team".into(), "platform".into())]);
        let mesh = MeshConfig {
            telemetry_resources: vec![
                make_telemetry(
                    "tel-match",
                    "ns",
                    PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("team".into(), "platform".into())]),
                            namespace: None,
                        },
                    },
                ),
                make_telemetry(
                    "tel-nomatch",
                    "ns",
                    PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("team".into(), "infra".into())]),
                            namespace: None,
                        },
                    },
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice =
            MeshSlice::from_gateway_config(&config, slice_request_with_labels("alpha", labels));
        assert_eq!(slice.telemetry_resources.len(), 1);
        assert_eq!(slice.telemetry_resources[0].name, "tel-match");
    }

    #[test]
    fn inferred_labels_keep_candidate_matching_selector_resources_as_superset() {
        let workload_a = make_workload(
            "alpha",
            "shared",
            HashMap::from([
                ("app".into(), "shared".into()),
                ("role".into(), "api".into()),
            ]),
        );
        let workload_b = make_workload(
            "alpha",
            "shared",
            HashMap::from([
                ("app".into(), "shared".into()),
                ("role".into(), "worker".into()),
            ]),
        );
        let workload_spiffe_id = workload_a.spiffe_id.to_string();
        let role_api_selector = WorkloadSelector {
            labels: HashMap::from([("role".into(), "api".into())]),
            namespace: Some("alpha".into()),
        };
        let mesh = MeshConfig {
            workloads: vec![workload_a, workload_b],
            peer_authentications: vec![
                make_peer_auth("pa-alpha", "alpha", None),
                make_peer_auth("pa-role-api", "alpha", Some(role_api_selector.clone())),
            ],
            request_authentications: vec![
                make_request_auth(
                    "ra-alpha",
                    "alpha",
                    PolicyScope::Namespace {
                        namespace: "alpha".into(),
                    },
                ),
                make_request_auth(
                    "ra-role-api",
                    "alpha",
                    PolicyScope::WorkloadSelector {
                        selector: role_api_selector.clone(),
                    },
                ),
            ],
            telemetry_resources: vec![
                make_telemetry(
                    "tel-alpha",
                    "alpha",
                    PolicyScope::Namespace {
                        namespace: "alpha".into(),
                    },
                ),
                make_telemetry(
                    "tel-role-api",
                    "alpha",
                    PolicyScope::WorkloadSelector {
                        selector: role_api_selector,
                    },
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let mut request = slice_request("alpha");
        request.workload_spiffe_id = Some(workload_spiffe_id);

        let slice = MeshSlice::from_gateway_config(&config, request);

        assert_eq!(
            slice.labels,
            BTreeMap::from([("app".into(), "shared".into())]),
            "only labels common to every matching workload should be authoritative for slice.labels"
        );
        assert!(
            slice.labels_ambiguous,
            "labels inferred from >1 shared-SPIFFE candidate must be marked ambiguous so the xDS \
             DP re-filters the candidate-any superset against its own labels"
        );
        // Candidate-any superset: the `role=api` selector resources match the
        // `api` candidate workload, so they are kept for the per-pod NodeWaypoint
        // and xDS DP-local-label consumers to re-filter — even though
        // slice.labels carries only the shared intersection. Narrowing them out
        // here would fail open for those consumers (codex P1s).
        assert_eq!(slice.peer_authentications.len(), 2);
        assert!(
            slice
                .peer_authentications
                .iter()
                .any(|p| p.name == "pa-role-api"),
            "candidate-matching selector PeerAuthentication kept as superset"
        );
        assert_eq!(slice.request_authentications.len(), 2);
        assert!(
            slice
                .request_authentications
                .iter()
                .any(|r| r.name == "ra-role-api"),
            "candidate-matching selector RequestAuthentication kept as superset"
        );
        assert_eq!(slice.telemetry_resources.len(), 2);
        assert!(
            slice
                .telemetry_resources
                .iter()
                .any(|t| t.name == "tel-role-api"),
            "candidate-matching selector Telemetry kept as superset"
        );
    }

    #[test]
    fn from_gateway_config_trust_bundles_and_multi_cluster_propagated() {
        let mut multi_cluster = make_multi_cluster();
        multi_cluster.east_west_gateways = vec![
            EastWestGateway {
                name: "gw-ns".into(),
                namespace: "ns".into(),
                host: "eastwest-ns.svc.cluster.local".into(),
                port: 15443,
                sni_hosts: vec!["*.ns.svc.cluster.local".into()],
                trust_domain: Some(td()),
                network: Some("network-ns".into()),
            },
            EastWestGateway {
                name: "gw-other".into(),
                namespace: "other".into(),
                host: "eastwest-other.svc.cluster.local".into(),
                port: 15443,
                sni_hosts: vec!["*.other.svc.cluster.local".into()],
                trust_domain: Some(td()),
                network: Some("network-other".into()),
            },
        ];

        let mesh = MeshConfig {
            trust_bundles: Some(make_trust_bundle_set()),
            multi_cluster: Some(multi_cluster),
            outbound_traffic_policy: None,
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("ns"));
        assert!(slice.trust_bundles.is_some());
        assert!(slice.multi_cluster.is_some());
        assert_eq!(
            slice.multi_cluster.as_ref().unwrap().local_cluster,
            Some("cluster-a".into())
        );
        assert_eq!(
            slice
                .multi_cluster
                .as_ref()
                .unwrap()
                .east_west_gateways
                .iter()
                .map(|gateway| gateway.namespace.as_str())
                .collect::<Vec<_>>(),
            vec!["ns"]
        );
    }

    #[test]
    fn from_gateway_config_version_set_from_loaded_at() {
        let config = config_with_mesh(MeshConfig::default());
        let slice = MeshSlice::from_gateway_config(&config, slice_request("ns"));
        assert_eq!(slice.version, config.loaded_at.to_rfc3339());
    }

    #[test]
    fn from_gateway_config_multiple_namespaces_only_requested_included() {
        let mesh = MeshConfig {
            workloads: vec![
                make_workload("ns-a", "svc-1", HashMap::new()),
                make_workload("ns-b", "svc-2", HashMap::new()),
                make_workload("ns-c", "svc-3", HashMap::new()),
            ],
            services: vec![
                make_service("ns-a", "svc-1"),
                make_service("ns-b", "svc-2"),
                make_service("ns-c", "svc-3"),
            ],
            peer_authentications: vec![
                make_peer_auth("pa-a", "ns-a", None),
                make_peer_auth("pa-b", "ns-b", None),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("ns-b"));
        assert_eq!(slice.workloads.len(), 1);
        assert_eq!(slice.workloads[0].namespace, "ns-b");
        assert_eq!(slice.services.len(), 1);
        assert_eq!(slice.services[0].namespace, "ns-b");
        assert_eq!(slice.peer_authentications.len(), 1);
        assert_eq!(slice.peer_authentications[0].name, "pa-b");
    }

    #[test]
    fn from_gateway_config_spiffe_id_resolves_workload_labels() {
        let td = td();
        let spiffe_id = SpiffeId::from_parts(&td, "ns/alpha/sa/web").unwrap();
        let workload_labels = HashMap::from([
            ("app".into(), "web".into()),
            ("tier".into(), "frontend".into()),
        ]);
        let mesh = MeshConfig {
            workloads: vec![make_workload("alpha", "web", workload_labels)],
            mesh_policies: vec![make_policy(
                "selector-policy",
                "alpha",
                PolicyScope::WorkloadSelector {
                    selector: WorkloadSelector {
                        labels: HashMap::from([("app".into(), "web".into())]),
                        namespace: None,
                    },
                },
            )],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        // Request has no labels but carries SPIFFE ID matching the workload.
        let request = MeshSliceRequest {
            node_id: "node-1".into(),
            namespace: "alpha".into(),
            workload_spiffe_id: Some(spiffe_id.to_string()),
            labels: BTreeMap::new(),
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            enforce_sidecar_egress: false,
            sidecar_egress_dry_run: false,
            enforce_sidecar_identity_narrowing: false,
            waypoint_name: None,
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
        };
        let slice = MeshSlice::from_gateway_config(&config, request);
        // The slice should inherit labels from the matched workload.
        assert_eq!(slice.labels.get("app"), Some(&"web".to_string()));
        assert_eq!(slice.labels.get("tier"), Some(&"frontend".to_string()));
        // A single matching workload is unambiguous: its labels are
        // authoritative, so the xDS DP keeps trusting the carrier.
        assert!(
            !slice.labels_ambiguous,
            "single-candidate inherited labels are authoritative, not ambiguous"
        );
        // The workload-selector policy should match via inherited labels.
        assert_eq!(slice.mesh_policies.len(), 1);
        assert_eq!(slice.mesh_policies[0].name, "selector-policy");
    }

    #[test]
    fn from_gateway_config_includes_selector_policies_for_ambiguous_spiffe_id() {
        let td = td();
        let spiffe_id = SpiffeId::from_parts(&td, "ns/alpha/sa/shared").unwrap();
        let mut web = make_workload(
            "alpha",
            "web",
            HashMap::from([("app".into(), "web".into())]),
        );
        let mut api = make_workload(
            "alpha",
            "api",
            HashMap::from([("app".into(), "api".into())]),
        );
        web.spiffe_id = spiffe_id.clone();
        api.spiffe_id = spiffe_id.clone();
        let mesh = MeshConfig {
            workloads: vec![web, api],
            mesh_policies: vec![make_policy(
                "web-selector-policy",
                "alpha",
                PolicyScope::WorkloadSelector {
                    selector: WorkloadSelector {
                        labels: HashMap::from([("app".into(), "web".into())]),
                        namespace: None,
                    },
                },
            )],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let request = MeshSliceRequest {
            node_id: "node-1".into(),
            namespace: "alpha".into(),
            workload_spiffe_id: Some(spiffe_id.to_string()),
            labels: BTreeMap::new(),
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            enforce_sidecar_egress: false,
            sidecar_egress_dry_run: false,
            enforce_sidecar_identity_narrowing: false,
            waypoint_name: None,
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
        };

        let slice = MeshSlice::from_gateway_config(&config, request);

        assert!(slice.labels.is_empty());
        assert!(
            slice.labels_ambiguous,
            "an empty intersection across >1 shared-SPIFFE candidates is still ambiguous"
        );
        assert_eq!(
            slice.mesh_policies.len(),
            1,
            "a selector policy matching any shared-SPIFFE candidate is kept (superset) for per-pod / DP-local re-filtering even when the label intersection is empty"
        );
        assert_eq!(slice.mesh_policies[0].name, "web-selector-policy");
    }

    #[test]
    fn from_gateway_config_inherits_common_labels_from_replicated_spiffe_id() {
        let td = td();
        let spiffe_id = SpiffeId::from_parts(&td, "ns/alpha/sa/shared").unwrap();
        let mut replica_a = make_workload(
            "alpha",
            "web",
            HashMap::from([
                ("app".into(), "web".into()),
                ("version".into(), "v1".into()),
                ("pod-template-hash".into(), "aaa".into()),
            ]),
        );
        let mut replica_b = make_workload(
            "alpha",
            "web",
            HashMap::from([
                ("app".into(), "web".into()),
                ("version".into(), "v1".into()),
                ("pod-template-hash".into(), "bbb".into()),
            ]),
        );
        replica_a.spiffe_id = spiffe_id.clone();
        replica_b.spiffe_id = spiffe_id.clone();
        let mesh = MeshConfig {
            workloads: vec![replica_a, replica_b],
            mesh_policies: vec![
                make_policy(
                    "common-selector-policy",
                    "alpha",
                    PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([
                                ("app".into(), "web".into()),
                                ("version".into(), "v1".into()),
                            ]),
                            namespace: None,
                        },
                    },
                ),
                make_policy(
                    "replica-specific-policy",
                    "alpha",
                    PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("pod-template-hash".into(), "aaa".into())]),
                            namespace: None,
                        },
                    },
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let request = MeshSliceRequest {
            node_id: "node-1".into(),
            namespace: "alpha".into(),
            workload_spiffe_id: Some(spiffe_id.to_string()),
            labels: BTreeMap::new(),
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            enforce_sidecar_egress: false,
            sidecar_egress_dry_run: false,
            enforce_sidecar_identity_narrowing: false,
            waypoint_name: None,
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
        };

        let slice = MeshSlice::from_gateway_config(&config, request);

        assert_eq!(slice.labels.get("app"), Some(&"web".to_string()));
        assert_eq!(slice.labels.get("version"), Some(&"v1".to_string()));
        assert!(!slice.labels.contains_key("pod-template-hash"));
        // slice.labels carries only the common intersection, but BOTH selector
        // policies are kept (candidate-any superset): the per-pod / DP-local
        // consumers re-filter, so a replica-specific policy must survive for the
        // replica it targets rather than being dropped CP-side (codex P1).
        assert_eq!(slice.mesh_policies.len(), 2);
        assert!(
            slice
                .mesh_policies
                .iter()
                .any(|policy| policy.name == "common-selector-policy")
        );
        assert!(
            slice
                .mesh_policies
                .iter()
                .any(|policy| policy.name == "replica-specific-policy"),
            "candidate-matching selector policy kept as superset for per-pod / DP-local re-filtering"
        );
    }

    #[test]
    fn from_gateway_config_identical_replica_labels_are_not_ambiguous() {
        // The common replica/endpoints case: several `Workload` records share a
        // SPIFFE id with IDENTICAL label maps. The intersection equals each set,
        // so the inferred labels are authoritative — the marker must stay false.
        // If it were set, the xDS DP would prefer its own (possibly stale or
        // partial) FERRUM_MESH_WORKLOAD_LABELS over the CP's correct labels and
        // could drop selector-scoped DENY/PeerAuth/JWT rules (Codex P2).
        let td = td();
        let spiffe_id = SpiffeId::from_parts(&td, "ns/alpha/sa/shared").unwrap();
        let labels = HashMap::from([
            ("app".into(), "web".into()),
            ("version".into(), "v1".into()),
        ]);
        let mut replica_a = make_workload("alpha", "web", labels.clone());
        let mut replica_b = make_workload("alpha", "web", labels.clone());
        let mut replica_c = make_workload("alpha", "web", labels);
        replica_a.spiffe_id = spiffe_id.clone();
        replica_b.spiffe_id = spiffe_id.clone();
        replica_c.spiffe_id = spiffe_id.clone();
        let mesh = MeshConfig {
            workloads: vec![replica_a, replica_b, replica_c],
            mesh_policies: vec![make_policy(
                "app-selector-policy",
                "alpha",
                PolicyScope::WorkloadSelector {
                    selector: WorkloadSelector {
                        labels: HashMap::from([("app".into(), "web".into())]),
                        namespace: None,
                    },
                },
            )],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let request = MeshSliceRequest {
            node_id: "node-1".into(),
            namespace: "alpha".into(),
            workload_spiffe_id: Some(spiffe_id.to_string()),
            labels: BTreeMap::new(),
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            enforce_sidecar_egress: false,
            sidecar_egress_dry_run: false,
            enforce_sidecar_identity_narrowing: false,
            waypoint_name: None,
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
        };

        let slice = MeshSlice::from_gateway_config(&config, request);

        assert_eq!(slice.labels.get("app"), Some(&"web".to_string()));
        assert_eq!(slice.labels.get("version"), Some(&"v1".to_string()));
        assert!(
            !slice.labels_ambiguous,
            "identical replica labels intersect to the full authoritative set; not ambiguous"
        );
        assert_eq!(slice.mesh_policies.len(), 1);
        assert_eq!(slice.mesh_policies[0].name, "app-selector-policy");
    }

    #[test]
    fn from_gateway_config_explicit_labels_override_workload_labels() {
        let td = td();
        let spiffe_id = SpiffeId::from_parts(&td, "ns/alpha/sa/web").unwrap();
        let workload_labels = HashMap::from([("app".into(), "web".into())]);
        let mesh = MeshConfig {
            workloads: vec![make_workload("alpha", "web", workload_labels)],
            mesh_policies: vec![make_policy(
                "explicit-labels-policy",
                "alpha",
                PolicyScope::WorkloadSelector {
                    selector: WorkloadSelector {
                        labels: HashMap::from([("custom".into(), "value".into())]),
                        namespace: None,
                    },
                },
            )],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        // Request carries explicit labels that differ from the workload's.
        let request = MeshSliceRequest {
            node_id: "node-1".into(),
            namespace: "alpha".into(),
            workload_spiffe_id: Some(spiffe_id.to_string()),
            labels: BTreeMap::from([("custom".into(), "value".into())]),
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            enforce_sidecar_egress: false,
            sidecar_egress_dry_run: false,
            enforce_sidecar_identity_narrowing: false,
            waypoint_name: None,
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
        };
        let slice = MeshSlice::from_gateway_config(&config, request);
        // Explicit labels should be used, not the workload's labels.
        assert_eq!(slice.labels.get("custom"), Some(&"value".to_string()));
        assert!(!slice.labels.contains_key("app"));
        assert_eq!(slice.mesh_policies.len(), 1);
    }

    // ── MeshSliceRequest helper tests ───────────────────────────────────

    #[test]
    fn mesh_slice_request_from_native_with_empty_spiffe_id() {
        let req = MeshSliceRequest::from_native(
            "node".into(),
            "ns".into(),
            String::new(),
            HashMap::new(),
        );
        assert!(req.workload_spiffe_id.is_none());
    }

    #[test]
    fn mesh_slice_request_from_native_with_nonempty_spiffe_id() {
        let req = MeshSliceRequest::from_native(
            "node".into(),
            "ns".into(),
            "spiffe://td/ns/foo/sa/bar".into(),
            HashMap::from([("k".into(), "v".into())]),
        );
        assert_eq!(
            req.workload_spiffe_id,
            Some("spiffe://td/ns/foo/sa/bar".into())
        );
        assert_eq!(req.labels.get("k"), Some(&"v".to_string()));
    }

    #[test]
    fn mesh_slice_request_from_xds_node_with_spiffe_prefix() {
        let req = MeshSliceRequest::from_xds_node("spiffe://td/ns/foo/sa/bar".into(), "ns".into());
        assert_eq!(
            req.workload_spiffe_id,
            Some("spiffe://td/ns/foo/sa/bar".into())
        );
    }

    #[test]
    fn mesh_slice_request_from_xds_node_without_spiffe_prefix() {
        let req = MeshSliceRequest::from_xds_node("my-node-id".into(), "ns".into());
        assert!(req.workload_spiffe_id.is_none());
        assert!(req.labels.is_empty());
    }

    // ── Private helper tests ────────────────────────────────────────────

    #[test]
    fn non_empty_returns_none_for_empty_string() {
        assert_eq!(non_empty(String::new()), None);
    }

    #[test]
    fn non_empty_returns_some_for_nonempty_string() {
        assert_eq!(non_empty("hello".into()), Some("hello".into()));
    }

    #[test]
    fn labels_to_btree_preserves_all_entries() {
        let hm = HashMap::from([("a".into(), "1".into()), ("b".into(), "2".into())]);
        let bt = labels_to_btree(&hm);
        assert_eq!(bt.len(), 2);
        assert_eq!(bt.get("a"), Some(&"1".to_string()));
        assert_eq!(bt.get("b"), Some(&"2".to_string()));
    }

    #[test]
    fn labels_to_btree_empty_map() {
        let bt = labels_to_btree(&HashMap::new());
        assert!(bt.is_empty());
    }

    // ── DestinationRule slice filtering ──────────────────────────────────

    #[test]
    fn from_gateway_config_filters_destination_rules_by_namespace() {
        use crate::modes::mesh::config::MeshDestinationRule;

        let mesh = MeshConfig {
            destination_rules: vec![
                MeshDestinationRule {
                    name: "in-ns".into(),
                    namespace: "ns".into(),
                    host: "reviews.ns.svc.cluster.local".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
                MeshDestinationRule {
                    name: "other-ns".into(),
                    namespace: "other".into(),
                    host: "reviews.other.svc.cluster.local".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
            ],
            ..MeshConfig::default()
        };
        let cfg = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&cfg, slice_request("ns"));

        assert_eq!(slice.destination_rules.len(), 1);
        assert_eq!(slice.destination_rules[0].namespace, "ns");
        assert_eq!(slice.destination_rules[0].name, "in-ns");
    }

    fn pa(
        name: &str,
        namespace: &str,
        selector: Option<WorkloadSelector>,
        mode: MtlsMode,
        port_overrides: HashMap<u16, MtlsMode>,
    ) -> PeerAuthentication {
        PeerAuthentication {
            name: name.to_string(),
            namespace: namespace.to_string(),
            scope: None,
            selector,
            mtls_mode: mode,
            port_overrides,
        }
    }

    fn pa_with_scope(
        name: &str,
        namespace: &str,
        scope: PolicyScope,
        mode: MtlsMode,
    ) -> PeerAuthentication {
        let selector = match &scope {
            PolicyScope::WorkloadSelector { selector } => Some(selector.clone()),
            PolicyScope::MeshWide | PolicyScope::Namespace { .. } => None,
        };
        PeerAuthentication {
            name: name.to_string(),
            namespace: namespace.to_string(),
            scope: Some(scope),
            selector,
            mtls_mode: mode,
            port_overrides: HashMap::new(),
        }
    }

    // ── MeshProxyConfig slice/resolution tests ──────────────────────────

    fn make_proxy_config(
        name: &str,
        namespace: &str,
        selector_labels: HashMap<String, String>,
        tracing_sampling: Option<f64>,
    ) -> MeshProxyConfig {
        let scope = if selector_labels.is_empty() {
            PolicyScope::Namespace {
                namespace: namespace.into(),
            }
        } else {
            PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels: selector_labels,
                    namespace: Some(namespace.into()),
                },
            }
        };
        MeshProxyConfig {
            name: name.into(),
            namespace: namespace.into(),
            scope,
            concurrency: None,
            image: None,
            environment: HashMap::new(),
            tracing_sampling,
        }
    }

    fn make_mesh_wide_proxy_config(
        name: &str,
        namespace: &str,
        tracing_sampling: Option<f64>,
    ) -> MeshProxyConfig {
        MeshProxyConfig {
            name: name.into(),
            namespace: namespace.into(),
            scope: PolicyScope::MeshWide,
            concurrency: None,
            image: None,
            environment: HashMap::new(),
            tracing_sampling,
        }
    }

    fn make_mesh_wide_selector_proxy_config(
        name: &str,
        namespace: &str,
        labels: HashMap<String, String>,
        tracing_sampling: Option<f64>,
    ) -> MeshProxyConfig {
        MeshProxyConfig {
            name: name.into(),
            namespace: namespace.into(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels,
                    namespace: None,
                },
            },
            concurrency: None,
            image: None,
            environment: HashMap::new(),
            tracing_sampling,
        }
    }

    #[test]
    fn no_peer_auth_defaults_to_permissive() {
        let mode =
            resolve_effective_mtls_mode(&[], "default", &HashMap::<String, String>::new(), 8080);
        assert_eq!(mode, MtlsMode::Permissive);
    }

    #[test]
    fn same_tier_peer_auth_resolves_fail_secure_to_more_restrictive_mode() {
        // Two namespace-tier PeerAuthentications match the same workload with
        // conflicting modes. The tie resolves FAIL-SECURE to the more-
        // restrictive mode (Strict > Permissive > Disable), independent of slice
        // iteration order and of the policies' names, so the inbound mTLS
        // posture can neither flap across pods/reconciles nor be downgraded by a
        // low-sorting policy name.
        let strict = pa(
            "zz-strict",
            "default",
            None,
            MtlsMode::Strict,
            HashMap::new(),
        );
        let permissive = pa(
            "aa-permissive",
            "default",
            None,
            MtlsMode::Permissive,
            HashMap::new(),
        );
        let labels = HashMap::<String, String>::new();

        // `aa-permissive` sorts before `zz-strict`, so a name tiebreak would
        // have picked Permissive; fail-secure must still pick Strict.
        let forward = vec![permissive.clone(), strict.clone()];
        assert_eq!(
            resolve_effective_mtls_mode(&forward, "default", &labels, 8080),
            MtlsMode::Strict,
            "the more-restrictive mode must win regardless of policy name order"
        );

        let reversed = vec![strict, permissive];
        assert_eq!(
            resolve_effective_mtls_mode(&reversed, "default", &labels, 8080),
            MtlsMode::Strict,
            "reversed slice order must resolve to the same fail-secure winner"
        );
    }

    #[test]
    fn same_tier_peer_auth_prefers_more_restrictive_mode_over_namespace_order() {
        // Mesh-wide policies from different namespaces both apply. The tie is
        // decided by mode, not by namespace string: Strict wins even though its
        // namespace sorts AFTER the conflicting Permissive policy's namespace.
        // This is what makes a customized root namespace that sorts after tenant
        // namespaces safe — namespace order can no longer downgrade mTLS.
        let strict = pa_with_scope(
            "mesh-default",
            "zzz-root",
            PolicyScope::MeshWide,
            MtlsMode::Strict,
        );
        let permissive = pa_with_scope(
            "mesh-default",
            "aaa-root",
            PolicyScope::MeshWide,
            MtlsMode::Permissive,
        );
        let labels = HashMap::<String, String>::new();

        let forward = vec![permissive.clone(), strict.clone()];
        assert_eq!(
            resolve_effective_mtls_mode(&forward, "default", &labels, 8080),
            MtlsMode::Strict,
            "Strict must win even though zzz-root sorts after aaa-root"
        );

        let reversed = vec![strict, permissive];
        assert_eq!(
            resolve_effective_mtls_mode(&reversed, "default", &labels, 8080),
            MtlsMode::Strict,
            "reversed slice order must resolve to the same winner"
        );
    }

    #[test]
    fn same_tier_peer_auth_equal_modes_resolve_deterministically() {
        // When two same-tier policies carry the SAME effective mode, the result
        // is identical regardless of slice order; the value-neutral
        // (namespace, name) tiebreak only selects a canonical winning policy,
        // never the resolved mode.
        let a = pa_with_scope(
            "zz-policy",
            "aaa-root",
            PolicyScope::MeshWide,
            MtlsMode::Permissive,
        );
        let b = pa_with_scope(
            "aa-policy",
            "zzz-root",
            PolicyScope::MeshWide,
            MtlsMode::Permissive,
        );
        let labels = HashMap::<String, String>::new();

        let forward = vec![a.clone(), b.clone()];
        assert_eq!(
            resolve_effective_mtls_mode(&forward, "default", &labels, 8080),
            MtlsMode::Permissive,
            "equal-mode same-tier policies resolve to that mode"
        );

        let reversed = vec![b, a];
        assert_eq!(
            resolve_effective_mtls_mode(&reversed, "default", &labels, 8080),
            MtlsMode::Permissive,
            "reversed slice order resolves to the same mode"
        );
    }

    #[test]
    fn single_namespace_scoped_policy() {
        let policies = vec![pa(
            "ns-strict",
            "default",
            None,
            MtlsMode::Strict,
            HashMap::new(),
        )];
        let mode = resolve_effective_mtls_mode(
            &policies,
            "default",
            &HashMap::<String, String>::new(),
            8080,
        );
        assert_eq!(mode, MtlsMode::Strict);
    }

    #[test]
    fn workload_selector_beats_namespace_scope() {
        let policies = vec![
            pa(
                "ns-strict",
                "default",
                None,
                MtlsMode::Strict,
                HashMap::new(),
            ),
            pa(
                "wl-permissive",
                "default",
                Some(WorkloadSelector {
                    labels: HashMap::from([("app".into(), "web".into())]),
                    namespace: None,
                }),
                MtlsMode::Permissive,
                HashMap::new(),
            ),
        ];
        let labels = HashMap::from([("app".to_string(), "web".to_string())]);
        let mode = resolve_effective_mtls_mode(&policies, "default", &labels, 8080);
        assert_eq!(mode, MtlsMode::Permissive);
    }

    #[test]
    fn namespace_scope_beats_mesh_wide_when_both_selector_none() {
        let policies = vec![
            pa_with_scope(
                "mesh-wide",
                "istio-system",
                PolicyScope::MeshWide,
                MtlsMode::Disable,
            ),
            pa_with_scope(
                "ns-strict",
                "default",
                PolicyScope::Namespace {
                    namespace: "default".to_string(),
                },
                MtlsMode::Strict,
            ),
        ];
        let mode = resolve_effective_mtls_mode(
            &policies,
            "default",
            &HashMap::<String, String>::new(),
            8080,
        );
        assert_eq!(mode, MtlsMode::Strict);
    }

    #[test]
    fn mesh_slice_carries_mesh_wide_peer_auth_to_workload_namespace() {
        let mut config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                peer_authentications: vec![pa_with_scope(
                    "mesh-strict",
                    "istio-system",
                    PolicyScope::MeshWide,
                    MtlsMode::Strict,
                )],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        config.loaded_at = chrono::Utc::now();

        let slice = MeshSlice::from_gateway_config(
            &config,
            MeshSliceRequest {
                node_id: "node-a".to_string(),
                namespace: "default".to_string(),
                workload_spiffe_id: None,
                labels: BTreeMap::new(),
                cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
                enforce_sidecar_egress: false,
                sidecar_egress_dry_run: false,
                enforce_sidecar_identity_narrowing: false,
                waypoint_name: None,
                ambient_udp_source_scoping: false,
                node_waypoint_capture_scoping: false,
            },
        );

        assert_eq!(slice.peer_authentications.len(), 1);
        assert_eq!(slice.resolve_effective_mtls_mode(8080), MtlsMode::Strict);
    }

    #[test]
    fn port_override_within_winning_policy() {
        let policies = vec![pa(
            "ns-strict",
            "default",
            Some(WorkloadSelector {
                labels: HashMap::from([("app".into(), "api".into())]),
                namespace: None,
            }),
            MtlsMode::Strict,
            HashMap::from([(8080, MtlsMode::Disable)]),
        )];
        let labels = HashMap::from([("app".to_string(), "api".to_string())]);
        // Port 8080 has an override to Disable.
        let mode = resolve_effective_mtls_mode(&policies, "default", &labels, 8080);
        assert_eq!(mode, MtlsMode::Disable);

        // Port 443 uses the top-level mode.
        let mode = resolve_effective_mtls_mode(&policies, "default", &labels, 443);
        assert_eq!(mode, MtlsMode::Strict);
    }

    #[test]
    fn selectorless_port_override_is_ignored() {
        let policies = vec![pa(
            "namespace-strict",
            "default",
            None,
            MtlsMode::Strict,
            HashMap::from([(8080, MtlsMode::Disable)]),
        )];

        assert_eq!(
            resolve_effective_mtls_mode(
                &policies,
                "default",
                &HashMap::<String, String>::new(),
                8080,
            ),
            MtlsMode::Strict,
            "portLevelMtls must not alter a selector-less namespace policy"
        );
    }

    #[test]
    fn empty_selector_is_not_workload_scoped_and_ignores_port_override() {
        let policy = pa(
            "empty-selector",
            "default",
            Some(WorkloadSelector::default()),
            MtlsMode::Strict,
            HashMap::from([(8080, MtlsMode::Disable)]),
        );

        assert!(!policy.has_workload_selector());
        assert_eq!(classify_peer_auth_scope(&policy), PeerAuthScope::Namespace);
        assert_eq!(
            resolve_effective_mtls_mode(
                std::slice::from_ref(&policy),
                "default",
                &HashMap::<String, String>::new(),
                8080,
            ),
            MtlsMode::Strict,
            "an explicit empty selector is a namespace default and cannot activate portLevelMtls"
        );

        let mesh_policy = pa_with_scope(
            "empty-root-selector",
            "istio-system",
            PolicyScope::WorkloadSelector {
                selector: WorkloadSelector::default(),
            },
            MtlsMode::Strict,
        );
        assert!(!mesh_policy.has_workload_selector());
        assert_eq!(
            classify_peer_auth_scope(&mesh_policy),
            PeerAuthScope::MeshWide,
            "an empty root selector is a mesh default, not workload scope"
        );
    }

    #[test]
    fn port_override_only_applies_to_winning_policy() {
        // Namespace policy has port override, but workload-selector policy
        // wins and has no override for the port.
        let policies = vec![
            pa(
                "ns-policy",
                "default",
                None,
                MtlsMode::Strict,
                HashMap::from([(8080, MtlsMode::Disable)]),
            ),
            pa(
                "wl-policy",
                "default",
                Some(WorkloadSelector {
                    labels: HashMap::from([("app".into(), "api".into())]),
                    namespace: None,
                }),
                MtlsMode::Permissive,
                HashMap::new(),
            ),
        ];
        let labels = HashMap::from([("app".to_string(), "api".to_string())]);
        // Workload selector wins; port 8080 has no override in winning policy.
        let mode = resolve_effective_mtls_mode(&policies, "default", &labels, 8080);
        assert_eq!(mode, MtlsMode::Permissive);
    }

    #[test]
    fn wrong_namespace_is_ignored() {
        let policies = vec![pa(
            "other-ns",
            "production",
            None,
            MtlsMode::Strict,
            HashMap::new(),
        )];
        let mode = resolve_effective_mtls_mode(
            &policies,
            "default",
            &HashMap::<String, String>::new(),
            8080,
        );
        assert_eq!(mode, MtlsMode::Permissive);
    }

    #[test]
    fn selector_labels_must_match() {
        let policies = vec![pa(
            "wl-strict",
            "default",
            Some(WorkloadSelector {
                labels: HashMap::from([("app".into(), "web".into())]),
                namespace: None,
            }),
            MtlsMode::Strict,
            HashMap::new(),
        )];
        // Labels don't match.
        let labels = HashMap::from([("app".to_string(), "api".to_string())]);
        let mode = resolve_effective_mtls_mode(&policies, "default", &labels, 8080);
        assert_eq!(mode, MtlsMode::Permissive);
    }

    #[test]
    fn mesh_slice_resolve_delegates_correctly() {
        let slice = MeshSlice {
            namespace: "default".to_string(),
            labels: BTreeMap::from([("app".to_string(), "web".to_string())]),
            peer_authentications: vec![
                pa(
                    "ns-disable",
                    "default",
                    None,
                    MtlsMode::Disable,
                    HashMap::new(),
                ),
                pa(
                    "wl-strict",
                    "default",
                    Some(WorkloadSelector {
                        labels: HashMap::from([("app".into(), "web".into())]),
                        namespace: None,
                    }),
                    MtlsMode::Strict,
                    HashMap::from([(443, MtlsMode::Permissive)]),
                ),
            ],
            ..MeshSlice::default()
        };
        // Workload selector wins (Strict), port 8080 has no override.
        assert_eq!(slice.resolve_effective_mtls_mode(8080), MtlsMode::Strict);
        // Port 443 has an override to Permissive in the winning policy.
        assert_eq!(slice.resolve_effective_mtls_mode(443), MtlsMode::Permissive);
    }

    #[test]
    fn classify_peer_auth_scope_ordering() {
        assert!(PeerAuthScope::WorkloadSelector > PeerAuthScope::Namespace);
        assert!(PeerAuthScope::Namespace > PeerAuthScope::MeshWide);
    }

    #[test]
    fn proxy_configs_filter_by_namespace_and_selector() {
        let mesh = MeshConfig {
            proxy_configs: vec![
                // In-namespace, no selector — applies to any workload in ns
                make_proxy_config("ns-default", "ns", HashMap::new(), Some(10.0)),
                // In-namespace, selector matches
                make_proxy_config(
                    "api-only",
                    "ns",
                    HashMap::from([("app".into(), "api".into())]),
                    Some(50.0),
                ),
                // In-namespace, selector does NOT match
                make_proxy_config(
                    "worker-only",
                    "ns",
                    HashMap::from([("app".into(), "worker".into())]),
                    Some(75.0),
                ),
                // Different namespace — filtered out
                make_proxy_config("other-ns", "other", HashMap::new(), Some(99.0)),
            ],
            ..MeshConfig::default()
        };
        let cfg = config_with_mesh(mesh);
        let request =
            slice_request_with_labels("ns", BTreeMap::from([("app".into(), "api".into())]));
        let slice = MeshSlice::from_gateway_config(&cfg, request);

        assert_eq!(slice.proxy_configs.len(), 2);
        let names: Vec<&str> = slice
            .proxy_configs
            .iter()
            .map(|pc| pc.name.as_str())
            .collect();
        assert!(names.contains(&"ns-default"));
        assert!(names.contains(&"api-only"));
    }

    #[test]
    fn resolved_proxy_config_prefers_workload_selector_over_namespace_default() {
        let mesh = MeshConfig {
            proxy_configs: vec![
                make_proxy_config("ns-default", "ns", HashMap::new(), Some(10.0)),
                make_proxy_config(
                    "api-only",
                    "ns",
                    HashMap::from([("app".into(), "api".into())]),
                    Some(50.0),
                ),
            ],
            ..MeshConfig::default()
        };
        let cfg = config_with_mesh(mesh);
        let request =
            slice_request_with_labels("ns", BTreeMap::from([("app".into(), "api".into())]));
        let slice = MeshSlice::from_gateway_config(&cfg, request);

        let resolved = slice.resolved_proxy_config().expect("resolved present");
        assert_eq!(resolved.name, "api-only");
        assert_eq!(resolved.tracing_sampling, Some(50.0));
    }

    #[test]
    fn resolved_proxy_config_returns_none_when_no_match() {
        let mesh = MeshConfig {
            proxy_configs: vec![make_proxy_config(
                "api-only",
                "ns",
                HashMap::from([("app".into(), "api".into())]),
                Some(50.0),
            )],
            ..MeshConfig::default()
        };
        let cfg = config_with_mesh(mesh);
        let request =
            slice_request_with_labels("ns", BTreeMap::from([("app".into(), "worker".into())]));
        let slice = MeshSlice::from_gateway_config(&cfg, request);

        assert!(slice.proxy_configs.is_empty());
        assert!(slice.resolved_proxy_config().is_none());
    }

    #[test]
    fn resolved_proxy_config_ascii_smallest_name_breaks_tie() {
        // Two workload-scoped ProxyConfigs that both match: tiebreaker must
        // be deterministic on the ASCII-smallest name.
        let mesh = MeshConfig {
            proxy_configs: vec![
                make_proxy_config(
                    "zzz-late",
                    "ns",
                    HashMap::from([("app".into(), "api".into())]),
                    Some(99.0),
                ),
                make_proxy_config(
                    "aaa-early",
                    "ns",
                    HashMap::from([("app".into(), "api".into())]),
                    Some(5.0),
                ),
            ],
            ..MeshConfig::default()
        };
        let cfg = config_with_mesh(mesh);
        let request =
            slice_request_with_labels("ns", BTreeMap::from([("app".into(), "api".into())]));
        let slice = MeshSlice::from_gateway_config(&cfg, request);

        // Both apply.
        assert_eq!(slice.proxy_configs.len(), 2);
        let resolved = slice.resolved_proxy_config().expect("resolved present");
        assert_eq!(resolved.name, "aaa-early");
        assert_eq!(resolved.tracing_sampling, Some(5.0));
    }

    #[test]
    fn content_eq_detects_proxy_configs_change() {
        let a = MeshSlice {
            proxy_configs: vec![make_proxy_config("p1", "ns", HashMap::new(), Some(10.0))],
            ..MeshSlice::default()
        };
        let mut b = a.clone();
        b.proxy_configs
            .push(make_proxy_config("p2", "ns", HashMap::new(), Some(50.0)));
        assert!(
            !a.content_eq(&b),
            "proxy_configs difference should be detected"
        );
    }

    #[test]
    fn mesh_wide_proxy_config_applies_across_namespaces() {
        // A MeshWide ProxyConfig (Istio root-namespace pattern with no
        // selector) must apply to workloads in any namespace, not just
        // the resource's own namespace.
        let mesh = MeshConfig {
            proxy_configs: vec![make_mesh_wide_proxy_config(
                "mesh-default",
                "istio-system",
                Some(10.0),
            )],
            ..MeshConfig::default()
        };
        let cfg = config_with_mesh(mesh);
        // Workload lives in "team-a", not the resource's "istio-system".
        let request = slice_request_with_labels("team-a", BTreeMap::new());
        let slice = MeshSlice::from_gateway_config(&cfg, request);

        assert_eq!(slice.proxy_configs.len(), 1);
        let resolved = slice.resolved_proxy_config().expect("resolved present");
        assert_eq!(resolved.tracing_sampling, Some(10.0));
    }

    #[test]
    fn mesh_wide_selector_proxy_config_applies_across_namespaces() {
        // A root-namespace ProxyConfig with a selector applies to matching
        // workloads in any namespace (PolicyScope::WorkloadSelector with
        // namespace=None).
        let mesh = MeshConfig {
            proxy_configs: vec![make_mesh_wide_selector_proxy_config(
                "mesh-api",
                "istio-system",
                HashMap::from([("app".into(), "api".into())]),
                Some(80.0),
            )],
            ..MeshConfig::default()
        };
        let cfg = config_with_mesh(mesh);
        // Workload in "team-a" with matching label.
        let request =
            slice_request_with_labels("team-a", BTreeMap::from([("app".into(), "api".into())]));
        let slice = MeshSlice::from_gateway_config(&cfg, request);

        assert_eq!(slice.proxy_configs.len(), 1);
        let resolved = slice.resolved_proxy_config().expect("resolved present");
        assert_eq!(resolved.tracing_sampling, Some(80.0));
    }

    #[test]
    fn namespace_scoped_proxy_config_overrides_mesh_wide_default() {
        // Workload-applicable Namespace-scoped ProxyConfig must outrank a
        // MeshWide default when both apply (specificity ordering).
        let mesh = MeshConfig {
            proxy_configs: vec![
                make_mesh_wide_proxy_config("zzz-mesh-default", "istio-system", Some(10.0)),
                make_proxy_config("ns-override", "ns", HashMap::new(), Some(50.0)),
            ],
            ..MeshConfig::default()
        };
        let cfg = config_with_mesh(mesh);
        let request = slice_request_with_labels("ns", BTreeMap::new());
        let slice = MeshSlice::from_gateway_config(&cfg, request);

        assert_eq!(slice.proxy_configs.len(), 2);
        let resolved = slice.resolved_proxy_config().expect("resolved present");
        assert_eq!(
            resolved.name, "ns-override",
            "Namespace-scoped must outrank MeshWide default"
        );
        assert_eq!(resolved.tracing_sampling, Some(50.0));
    }

    #[test]
    fn workload_selector_outranks_mesh_wide_default() {
        // WorkloadSelector beats MeshWide even when both match.
        let mesh = MeshConfig {
            proxy_configs: vec![
                make_mesh_wide_proxy_config("aaa-mesh-default", "istio-system", Some(10.0)),
                make_proxy_config(
                    "zzz-workload",
                    "ns",
                    HashMap::from([("app".into(), "api".into())]),
                    Some(90.0),
                ),
            ],
            ..MeshConfig::default()
        };
        let cfg = config_with_mesh(mesh);
        let request =
            slice_request_with_labels("ns", BTreeMap::from([("app".into(), "api".into())]));
        let slice = MeshSlice::from_gateway_config(&cfg, request);

        assert_eq!(slice.proxy_configs.len(), 2);
        let resolved = slice.resolved_proxy_config().expect("resolved present");
        assert_eq!(resolved.name, "zzz-workload");
        assert_eq!(resolved.tracing_sampling, Some(90.0));
    }

    // ── Outbound registry builder ─────────────────────────────────────────

    #[test]
    fn build_known_destinations_emits_service_forms_and_ports() {
        use crate::modes::mesh::config::AppProtocol;

        let slice = MeshSlice {
            namespace: "default".into(),
            services: vec![MeshService {
                cluster_ips: Vec::new(),
                name: "reviews".into(),
                namespace: "default".into(),
                ports: vec![crate::modes::mesh::config::ServicePort {
                    port: 8080,
                    protocol: AppProtocol::Http,
                    name: Some("http".into()),
                    target_port: None,
                }],
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            }],
            ..MeshSlice::default()
        };

        let entries = slice.build_known_destinations("cluster.local");
        assert!(entries.contains(&"reviews".to_string()));
        assert!(entries.contains(&"reviews.default".to_string()));
        assert!(entries.contains(&"reviews.default.svc".to_string()));
        assert!(entries.contains(&"reviews.default.svc.cluster.local".to_string()));
        assert!(entries.contains(&"reviews.default.svc.cluster.local:8080".to_string()));
        assert!(entries.contains(&"reviews.default.svc:8080".to_string()));
        assert!(entries.contains(&"reviews.default:8080".to_string()));
    }

    #[test]
    fn build_known_destinations_emits_any_port_marker_when_ports_absent() {
        let slice = MeshSlice {
            namespace: "default".into(),
            services: vec![MeshService {
                cluster_ips: Vec::new(),
                name: "ratings".into(),
                namespace: "default".into(),
                ports: Vec::new(),
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            }],
            ..MeshSlice::default()
        };

        let entries = slice.build_known_destinations("cluster.local");
        assert!(entries.contains(&"ratings".to_string()));
        assert!(entries.contains(&"ratings:*".to_string()));
        assert!(entries.contains(&"ratings.default:*".to_string()));
        assert!(entries.contains(&"ratings.default.svc:*".to_string()));
        assert!(entries.contains(&"ratings.default.svc.cluster.local:*".to_string()));
    }

    #[test]
    fn build_known_destinations_scopes_bare_service_names_to_local_namespace() {
        use crate::modes::mesh::config::{AppProtocol, ServicePort};

        let http_port = ServicePort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".into()),
            target_port: None,
        };
        let slice = MeshSlice {
            namespace: "default".into(),
            services: vec![
                MeshService {
                    cluster_ips: Vec::new(),
                    name: "reviews".into(),
                    namespace: "default".into(),
                    ports: vec![http_port.clone()],
                    workloads: Vec::new(),
                    protocol_overrides: HashMap::new(),
                },
                MeshService {
                    cluster_ips: Vec::new(),
                    name: "ratings".into(),
                    namespace: "payments".into(),
                    ports: vec![http_port],
                    workloads: Vec::new(),
                    protocol_overrides: HashMap::new(),
                },
            ],
            ..MeshSlice::default()
        };

        let entries = slice.build_known_destinations("cluster.local");
        assert!(entries.contains(&"reviews".to_string()));
        assert!(!entries.contains(&"ratings".to_string()));
        assert!(entries.contains(&"ratings.payments".to_string()));
        assert!(entries.contains(&"ratings.payments.svc.cluster.local:8080".to_string()));
    }

    #[test]
    fn build_known_destinations_normalizes_cluster_domain_and_trailing_dots() {
        use crate::modes::mesh::config::{AppProtocol, ServicePort};

        let slice = MeshSlice {
            namespace: "default".into(),
            services: vec![MeshService {
                cluster_ips: Vec::new(),
                name: "Reviews".into(),
                namespace: "Default".into(),
                ports: vec![ServicePort {
                    port: 8080,
                    protocol: AppProtocol::Http,
                    name: None,
                    target_port: None,
                }],
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            }],
            ..MeshSlice::default()
        };

        let entries = slice.build_known_destinations("Cluster.Local.");
        assert!(entries.contains(&"reviews.default.svc.cluster.local".to_string()));
        assert!(entries.contains(&"reviews.default.svc.cluster.local:8080".to_string()));
    }

    #[test]
    fn build_known_destinations_includes_service_entries() {
        use crate::modes::mesh::config::{
            AppProtocol, MeshEndpoint, Resolution, ServiceEntry, ServiceEntryLocation, ServicePort,
        };

        let slice = MeshSlice {
            service_entries: vec![ServiceEntry {
                name: "external-api".into(),
                namespace: "default".into(),
                hosts: vec!["API.EXAMPLE.COM.".into()],
                endpoints: vec![MeshEndpoint {
                    address: "10.0.0.1".into(),
                    ports: HashMap::new(),
                    labels: HashMap::new(),
                    network: None,
                }],
                resolution: Resolution::Static,
                location: ServiceEntryLocation::MeshExternal,
                ports: vec![ServicePort {
                    port: 443,
                    protocol: AppProtocol::Tls,
                    name: Some("https".into()),
                    target_port: None,
                }],
                export_to: Vec::new(),
                workload_selector: None,
            }],
            ..MeshSlice::default()
        };

        let entries = slice.build_known_destinations("cluster.local");
        assert!(entries.contains(&"api.example.com".to_string()));
        assert!(entries.contains(&"api.example.com:443".to_string()));
    }

    #[test]
    fn build_known_destinations_brackets_workload_ipv6_addresses() {
        let trust_domain = TrustDomain::new("cluster.local").unwrap();
        let slice = MeshSlice {
            workloads: vec![Workload {
                spiffe_id: SpiffeId::new("spiffe://cluster.local/ns/default/sa/default")
                    .expect("valid spiffe id"),
                selector: WorkloadSelector {
                    labels: HashMap::new(),
                    namespace: Some("default".into()),
                },
                service_name: "v6".into(),
                addresses: vec!["2001:db8::10".into()],
                ports: vec![WorkloadPort {
                    port: 8080,
                    protocol: crate::modes::mesh::config::AppProtocol::Http,
                    name: Some("http".into()),
                }],
                trust_domain,
                namespace: "default".into(),
                network: None,
                cluster: None,
                weight: None,
                locality: None,
                service_account: None,
                pod_uid: None,
                node_waypoint: None,
                remote_provenance: false,
            }],
            ..MeshSlice::default()
        };

        let entries = slice.build_known_destinations("cluster.local");
        assert!(entries.contains(&"[2001:db8::10]".to_string()));
        assert!(entries.contains(&"[2001:db8::10]:8080".to_string()));
        assert!(!entries.contains(&"2001:db8::10".to_string()));
    }

    #[test]
    fn build_known_destinations_canonicalizes_bracketed_ipv6_addresses() {
        let trust_domain = TrustDomain::new("cluster.local").unwrap();
        let slice = MeshSlice {
            workloads: vec![Workload {
                spiffe_id: SpiffeId::new("spiffe://cluster.local/ns/default/sa/default")
                    .expect("valid spiffe id"),
                selector: WorkloadSelector {
                    labels: HashMap::new(),
                    namespace: Some("default".into()),
                },
                service_name: "v6".into(),
                addresses: vec!["[2001:0DB8::10]".into()],
                ports: Vec::new(),
                trust_domain,
                namespace: "default".into(),
                network: None,
                cluster: None,
                weight: None,
                locality: None,
                service_account: None,
                pod_uid: None,
                node_waypoint: None,
                remote_provenance: false,
            }],
            ..MeshSlice::default()
        };

        let entries = slice.build_known_destinations("cluster.local");
        assert!(entries.contains(&"[2001:db8::10]".to_string()));
        assert!(!entries.contains(&"[2001:0db8::10]".to_string()));
    }

    #[test]
    fn build_known_destinations_is_sorted_and_deduplicated() {
        use crate::modes::mesh::config::{AppProtocol, ServicePort};

        let slice = MeshSlice {
            namespace: "default".into(),
            services: vec![
                MeshService {
                    cluster_ips: Vec::new(),
                    name: "zzz".into(),
                    namespace: "default".into(),
                    ports: vec![ServicePort {
                        port: 8080,
                        protocol: AppProtocol::Http,
                        name: None,
                        target_port: None,
                    }],
                    workloads: Vec::new(),
                    protocol_overrides: HashMap::new(),
                },
                MeshService {
                    cluster_ips: Vec::new(),
                    name: "aaa".into(),
                    namespace: "default".into(),
                    ports: vec![ServicePort {
                        port: 8080,
                        protocol: AppProtocol::Http,
                        name: None,
                        target_port: None,
                    }],
                    workloads: Vec::new(),
                    protocol_overrides: HashMap::new(),
                },
            ],
            ..MeshSlice::default()
        };

        let entries = slice.build_known_destinations("cluster.local");
        let aaa_idx = entries.iter().position(|e| e == "aaa").expect("aaa");
        let zzz_idx = entries.iter().position(|e| e == "zzz").expect("zzz");
        assert!(aaa_idx < zzz_idx, "entries must be sorted alphabetically");
        // No duplicates (HashSet → Vec)
        let mut dedup = entries.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(dedup.len(), entries.len());
    }

    // ── Sidecar egress scoping (FERRUM_MESH_SIDECAR_ENFORCED) ────────────

    fn make_sidecar(
        name: &str,
        namespace: &str,
        workload_selector: Option<WorkloadSelector>,
        egress_hosts: Vec<Vec<&str>>,
    ) -> MeshSidecar {
        make_sidecar_with_ports(
            name,
            namespace,
            workload_selector,
            egress_hosts
                .into_iter()
                .map(|hosts| (hosts, None))
                .collect(),
        )
    }

    fn make_sidecar_with_ports(
        name: &str,
        namespace: &str,
        workload_selector: Option<WorkloadSelector>,
        egress: Vec<(Vec<&str>, Option<u16>)>,
    ) -> MeshSidecar {
        MeshSidecar {
            name: name.into(),
            namespace: namespace.into(),
            workload_selector,
            egress_inherits_defaults: false,
            egress: egress
                .into_iter()
                .map(|(hosts, port)| MeshSidecarEgress {
                    hosts: hosts.into_iter().map(String::from).collect(),
                    port,
                })
                .collect(),
            ingress_declared: false,
            ingress: Vec::new(),
            outbound_traffic_policy: None,
        }
    }

    fn make_inheriting_sidecar(
        name: &str,
        namespace: &str,
        workload_selector: WorkloadSelector,
    ) -> MeshSidecar {
        MeshSidecar {
            name: name.into(),
            namespace: namespace.into(),
            workload_selector: Some(workload_selector),
            egress_inherits_defaults: true,
            egress: Vec::new(),
            ingress_declared: false,
            ingress: Vec::new(),
            outbound_traffic_policy: None,
        }
    }

    fn make_se_with_host(
        name: &str,
        namespace: &str,
        host: &str,
        export_to: Vec<String>,
    ) -> ServiceEntry {
        make_se_with_host_and_ports(name, namespace, host, &[443], export_to)
    }

    fn make_se_with_host_and_ports(
        name: &str,
        namespace: &str,
        host: &str,
        ports: &[u16],
        export_to: Vec<String>,
    ) -> ServiceEntry {
        ServiceEntry {
            name: name.into(),
            namespace: namespace.into(),
            hosts: vec![host.into()],
            endpoints: Vec::new(),
            resolution: crate::modes::mesh::config::Resolution::None,
            location: ServiceEntryLocation::MeshExternal,
            ports: ports
                .iter()
                .map(|port| ServicePort {
                    port: *port,
                    protocol: AppProtocol::Http2,
                    name: None,
                    target_port: None,
                })
                .collect(),
            export_to,
            workload_selector: None,
        }
    }

    fn slice_request_enforced(namespace: &str) -> MeshSliceRequest {
        MeshSliceRequest {
            node_id: "node-1".into(),
            namespace: namespace.into(),
            workload_spiffe_id: None,
            waypoint_name: None,
            labels: BTreeMap::new(),
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            enforce_sidecar_egress: true,
            sidecar_egress_dry_run: false,
            enforce_sidecar_identity_narrowing: false,
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
        }
    }

    fn slice_request_enforced_with_labels(
        namespace: &str,
        labels: BTreeMap<String, String>,
    ) -> MeshSliceRequest {
        MeshSliceRequest {
            node_id: "node-1".into(),
            namespace: namespace.into(),
            workload_spiffe_id: None,
            waypoint_name: None,
            labels,
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            enforce_sidecar_egress: true,
            sidecar_egress_dry_run: false,
            enforce_sidecar_identity_narrowing: false,
            ambient_udp_source_scoping: false,
            node_waypoint_capture_scoping: false,
        }
    }

    fn slice_request_dry_run(namespace: &str) -> MeshSliceRequest {
        MeshSliceRequest {
            namespace: namespace.to_string(),
            sidecar_egress_dry_run: true,
            ..MeshSliceRequest::default()
        }
    }

    fn slice_request_enforced_with_identity_narrowing(namespace: &str) -> MeshSliceRequest {
        MeshSliceRequest {
            enforce_sidecar_identity_narrowing: true,
            ..slice_request_enforced(namespace)
        }
    }

    fn slice_request_identity_narrowing_only(namespace: &str) -> MeshSliceRequest {
        MeshSliceRequest {
            enforce_sidecar_egress: false,
            enforce_sidecar_identity_narrowing: true,
            ..slice_request_enforced(namespace)
        }
    }

    fn port_numbers(ports: &[ServicePort]) -> Vec<u16> {
        ports.iter().map(|port| port.port).collect()
    }

    #[test]
    fn sidecar_dry_run_keeps_services_but_reports_would_be_scope() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["./reviews"]],
            )],
            services: vec![
                make_service_with_ports("alpha", "reviews", &[80, 8080]),
                make_service_with_ports("alpha", "ratings", &[9090]),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_dry_run("alpha"));

        assert_eq!(
            slice
                .services
                .iter()
                .map(|service| service.name.as_str())
                .collect::<Vec<_>>(),
            vec!["reviews", "ratings"]
        );
        let scope = slice
            .sidecar_egress_scope
            .as_ref()
            .expect("dry-run scope is recorded");
        assert!(!scope.sidecar_enforced);
        assert!(scope.dry_run);
        assert!(!scope.sidecar_applied);
        assert_eq!(scope.sidecar_admitted_services, 1);
        assert_eq!(scope.sidecar_denied_services, 1);
        assert_eq!(scope.services.len(), 1);
        assert_eq!(scope.services[0].name, "reviews");
        assert_eq!(scope.services[0].ports, vec![80, 8080]);
        assert!(
            scope
                .known_destinations
                .contains(&"reviews.alpha.svc.cluster.local:8080".to_string())
        );
        assert!(
            !scope
                .known_destinations
                .contains(&"ratings.alpha.svc.cluster.local:9090".to_string())
        );
    }

    #[test]
    fn sidecar_narrowing_filters_other_namespace_service_entries() {
        // Sidecar restricts egress to same-namespace hosts; ServiceEntry in
        // another namespace must be filtered out. Both entries export to `*`
        // so visibility alone would let them both through — only sidecar
        // narrowing should remove the "other" one.
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["./reviews.alpha.svc.cluster.local"]],
            )],
            service_entries: vec![
                make_se_with_host(
                    "reviews-local",
                    "alpha",
                    "reviews.alpha.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "external-other",
                    "beta",
                    "external.beta.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "reviews-local");
    }

    #[test]
    fn sidecar_narrowing_allow_all_pattern_is_noop() {
        // `*/*` admits everything — slice should look identical to today.
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar("default-sc", "alpha", None, vec![vec!["*/*"]])],
            service_entries: vec![
                make_se_with_host(
                    "reviews-local",
                    "alpha",
                    "reviews.alpha.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "external-other",
                    "beta",
                    "external.beta.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.service_entries.len(), 2);
    }

    #[test]
    fn sidecar_narrowing_workload_selector_only_matches_one_workload() {
        // Sidecar targets `app=frontend`. A workload with `app=frontend`
        // gets narrowed; a workload with `app=backend` falls through to no
        // sidecar (no namespace-default sidecar), so it sees the full set.
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "frontend-sc",
                "alpha",
                Some(WorkloadSelector {
                    labels: HashMap::from([("app".into(), "frontend".into())]),
                    namespace: None,
                }),
                vec![vec!["./reviews.alpha.svc.cluster.local"]],
            )],
            service_entries: vec![
                make_se_with_host(
                    "reviews",
                    "alpha",
                    "reviews.alpha.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "other",
                    "alpha",
                    "other.alpha.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);

        // Frontend workload — narrowed.
        let frontend_labels = BTreeMap::from([("app".into(), "frontend".into())]);
        let frontend_slice = MeshSlice::from_gateway_config(
            &config,
            slice_request_enforced_with_labels("alpha", frontend_labels),
        );
        assert_eq!(frontend_slice.service_entries.len(), 1);
        assert_eq!(frontend_slice.service_entries[0].name, "reviews");

        // Backend workload — no sidecar applies, no narrowing.
        let backend_labels = BTreeMap::from([("app".into(), "backend".into())]);
        let backend_slice = MeshSlice::from_gateway_config(
            &config,
            slice_request_enforced_with_labels("alpha", backend_labels),
        );
        assert_eq!(backend_slice.service_entries.len(), 2);
    }

    #[test]
    fn sidecar_narrowing_disabled_when_flag_unset() {
        // Even with an aggressive Sidecar present, the default flag
        // (enforce_sidecar_egress=false) skips narrowing entirely.
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "deny-most",
                "alpha",
                None,
                vec![vec!["./reviews.alpha.svc.cluster.local"]],
            )],
            service_entries: vec![
                make_se_with_host(
                    "reviews",
                    "alpha",
                    "reviews.alpha.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "external",
                    "beta",
                    "external.beta.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        // slice_request(..) is the existing helper with the flag false.
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(
            slice.service_entries.len(),
            2,
            "narrowing must not fire when the flag is false"
        );
    }

    #[test]
    fn sidecar_narrowing_namespace_wildcard_admits_namespace() {
        // `beta/*` admits anything in `beta`.
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar("ns-sc", "alpha", None, vec![vec!["beta/*"]])],
            service_entries: vec![
                make_se_with_host(
                    "reviews-beta",
                    "beta",
                    "reviews.beta.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "reviews-gamma",
                    "gamma",
                    "reviews.gamma.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "reviews-beta");
    }

    #[test]
    fn sidecar_narrowing_any_namespace_host_pattern_matches_anywhere() {
        // `*/reviews.alpha.svc.cluster.local` admits the host in ANY namespace.
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "global-sc",
                "alpha",
                None,
                vec![vec!["*/reviews.alpha.svc.cluster.local"]],
            )],
            service_entries: vec![
                make_se_with_host(
                    "reviews-alpha",
                    "alpha",
                    "reviews.alpha.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "reviews-cloned-in-beta",
                    "beta",
                    "reviews.alpha.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "unrelated",
                    "beta",
                    "unrelated.beta.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        // Both entries with that host across alpha + beta should match.
        assert_eq!(slice.service_entries.len(), 2);
    }

    #[test]
    fn sidecar_narrowing_captures_local_inbound_services_without_widening_egress() {
        // Two pods share the service account SPIFFE `sa/shared` but back
        // different services (`reviews` vs `ratings`) and carry different labels.
        // Egress `./checkout` admits only `checkout`. The local workload is the
        // `reviews` pod (label app=reviews). Expectations:
        //  - `services` (egress/outbound view) is narrowed to `checkout` only —
        //    `reviews` is NOT folded back in, so the outbound registry / egress
        //    scope is not widened (L577).
        //  - `local_inbound_services` (inbound-only view) carries `reviews`
        //    un-narrowed so its inbound mTLS traffic doesn't 404.
        //  - `ratings` shares the SPIFFE but its labels don't match the local
        //    workload, so it is NOT treated as local (L575).
        let shared_spiffe = "spiffe://cluster.local/ns/alpha/sa/shared";
        let mut reviews_wl = make_workload(
            "alpha",
            "reviews",
            HashMap::from([("app".to_string(), "reviews".to_string())]),
        );
        reviews_wl.spiffe_id = SpiffeId::new(shared_spiffe).unwrap();
        let mut ratings_wl = make_workload(
            "alpha",
            "ratings",
            HashMap::from([("app".to_string(), "ratings".to_string())]),
        );
        ratings_wl.spiffe_id = SpiffeId::new(shared_spiffe).unwrap();
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["./checkout"]],
            )],
            workloads: vec![reviews_wl, ratings_wl],
            services: vec![
                make_service("alpha", "reviews"),
                make_service("alpha", "ratings"),
                make_service("alpha", "checkout"),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let request = MeshSliceRequest {
            workload_spiffe_id: Some(shared_spiffe.to_string()),
            ..slice_request_enforced_with_labels(
                "alpha",
                BTreeMap::from([("app".to_string(), "reviews".to_string())]),
            )
        };
        let slice = MeshSlice::from_gateway_config(&config, request);

        // L577: egress-narrowed `services` is NOT widened by the inbound view.
        assert!(
            !slice.services.iter().any(|s| s.name == "reviews"),
            "the local service must not be folded back into the egress `services` view"
        );
        assert!(
            slice.services.iter().any(|s| s.name == "checkout"),
            "an egress-admitted service stays in `services`"
        );
        // Inbound view carries the local service un-narrowed.
        assert!(
            slice
                .local_inbound_services
                .iter()
                .any(|s| s.name == "reviews"),
            "the local workload's own service must be captured for inbound serving"
        );
        // L575: a SPIFFE-sharing but label-mismatched service is not local.
        assert!(
            !slice
                .local_inbound_services
                .iter()
                .any(|s| s.name == "ratings"),
            "a service sharing the service-account SPIFFE but not the local pod's labels is not local"
        );
    }

    #[test]
    fn sidecar_ingress_resolves_and_stamps_owner_under_enforcement() {
        // End-to-end: a workload-scoped Sidecar with two ingress entries (one
        // supported loopback HTTP listener, one unix-socket that can't be
        // modeled). Under enforcement the slice resolves ONLY the supported
        // listener into `local_ingress_listeners`, stamped with the local
        // service owner identity for forward-derived materialization.
        let spiffe = "spiffe://cluster.local/ns/alpha/sa/reviews";
        let mut reviews_wl = make_workload(
            "alpha",
            "reviews",
            HashMap::from([("app".to_string(), "reviews".to_string())]),
        );
        reviews_wl.spiffe_id = SpiffeId::new(spiffe).unwrap();
        let mut sidecar = make_sidecar(
            "reviews-sc",
            "alpha",
            Some(WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "reviews".to_string())]),
                namespace: Some("alpha".to_string()),
            }),
            vec![vec!["./checkout"]],
        );
        sidecar.ingress = vec![
            MeshSidecarIngress {
                port: 8443,
                protocol: AppProtocol::Http,
                name: Some("https".to_string()),
                bind: None,
                default_endpoint: "127.0.0.1:8080".to_string(),
            },
            MeshSidecarIngress {
                port: 9000,
                protocol: AppProtocol::Grpc,
                name: None,
                bind: None,
                default_endpoint: "unix:///var/run/grpc.sock".to_string(),
            },
        ];
        let mesh = MeshConfig {
            sidecars: vec![sidecar],
            workloads: vec![reviews_wl],
            services: vec![make_service("alpha", "reviews")],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let request = MeshSliceRequest {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..slice_request_enforced_with_labels(
                "alpha",
                BTreeMap::from([("app".to_string(), "reviews".to_string())]),
            )
        };
        let slice = MeshSlice::from_gateway_config(&config, request);

        assert_eq!(
            slice.local_ingress_listeners.len(),
            1,
            "only the supported loopback HTTP listener resolves; the unix-socket entry is dropped"
        );
        let listener = &slice.local_ingress_listeners[0];
        assert_eq!(listener.port, 8443);
        assert_eq!(listener.endpoint_host, "127.0.0.1");
        assert_eq!(listener.endpoint_port, 8080);
        assert_eq!(
            listener.owner_namespace, "alpha",
            "owner stamped from the resolved local service"
        );
        assert_eq!(listener.owner_service, "reviews");
        assert!(
            slice.sidecar_ingress_declared,
            "the applicable Sidecar declared a non-empty ingress[]"
        );
        // Codex round-4 P2: BOTH entries are HTTP-family on distinct ports (8443
        // http + 9000 grpc), so the DECLARED count is 2 even though the unix://
        // gRPC entry did not resolve. This is what keeps the router's ingress
        // group ambiguous (it exceeds the 1 resolved listener), so an
        // orig-dst-less request fails closed instead of routing the skipped
        // listener's traffic to the survivor.
        assert_eq!(
            slice.declared_ingress_http_ports, 2,
            "both HTTP-family ingress ports are DECLARED even though the unix:// gRPC entry \
             produced no resolved listener"
        );
    }

    #[test]
    fn sidecar_ingress_only_resolves_independent_of_egress_scope() {
        // F6 §6.2 (Finding 4): a Sidecar that declares ONLY `ingress[]` and
        // omits `spec.egress` (egress_inherits_defaults = true) with NO
        // namespace/root default to inherit resolves NO egress scope —
        // `applicable_sidecar` is None. The ingress listeners must STILL resolve
        // and the local-inbound service view must STILL be stamped (decoupled
        // from egress-scope inheritance), so the listeners get a host anchor
        // instead of being cleared.
        let spiffe = "spiffe://cluster.local/ns/alpha/sa/reviews";
        let mut reviews_wl = make_workload(
            "alpha",
            "reviews",
            HashMap::from([("app".to_string(), "reviews".to_string())]),
        );
        reviews_wl.spiffe_id = SpiffeId::new(spiffe).unwrap();
        // Ingress-only Sidecar: egress omitted → inherits defaults, but there is
        // no namespace/root default Sidecar, so egress resolves to None.
        let mut sidecar = MeshSidecar {
            name: "reviews-sc".into(),
            namespace: "alpha".into(),
            workload_selector: Some(WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "reviews".to_string())]),
                namespace: Some("alpha".to_string()),
            }),
            egress_inherits_defaults: true,
            egress: Vec::new(),
            ingress_declared: false,
            ingress: Vec::new(),
            outbound_traffic_policy: None,
        };
        sidecar.ingress = vec![MeshSidecarIngress {
            port: 8443,
            protocol: AppProtocol::Http,
            name: None,
            bind: None,
            default_endpoint: "127.0.0.1:8080".to_string(),
        }];
        let mesh = MeshConfig {
            sidecars: vec![sidecar],
            workloads: vec![reviews_wl],
            services: vec![make_service("alpha", "reviews")],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let request = MeshSliceRequest {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..slice_request_enforced_with_labels(
                "alpha",
                BTreeMap::from([("app".to_string(), "reviews".to_string())]),
            )
        };
        let slice = MeshSlice::from_gateway_config(&config, request);

        assert!(
            slice.sidecar_ingress_declared,
            "ingress-only Sidecar still records the declared marker"
        );
        assert_eq!(
            slice.local_ingress_listeners.len(),
            1,
            "ingress listener resolves even though no egress scope applied"
        );
        let listener = &slice.local_ingress_listeners[0];
        assert_eq!(
            listener.owner_service, "reviews",
            "listener owner stamped from the independently-resolved local service"
        );
        assert_eq!(listener.owner_namespace, "alpha");
        assert!(
            slice
                .local_inbound_services
                .iter()
                .any(|s| s.name == "reviews" && s.namespace == "alpha"),
            "local-inbound service view is populated independent of egress scope"
        );
    }

    #[test]
    fn sidecar_ingress_not_resolved_under_dry_run() {
        // Dry-run reports egress but changes nothing — ingress is NOT
        // materialized (it is a behavior change).
        let spiffe = "spiffe://cluster.local/ns/alpha/sa/reviews";
        let mut reviews_wl = make_workload(
            "alpha",
            "reviews",
            HashMap::from([("app".to_string(), "reviews".to_string())]),
        );
        reviews_wl.spiffe_id = SpiffeId::new(spiffe).unwrap();
        let mut sidecar = make_sidecar("reviews-sc", "alpha", None, vec![vec!["./checkout"]]);
        sidecar.ingress = vec![MeshSidecarIngress {
            port: 8443,
            protocol: AppProtocol::Http,
            name: None,
            bind: None,
            default_endpoint: "127.0.0.1:8080".to_string(),
        }];
        let mesh = MeshConfig {
            sidecars: vec![sidecar],
            workloads: vec![reviews_wl],
            services: vec![make_service("alpha", "reviews")],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let request = MeshSliceRequest {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..slice_request_dry_run("alpha")
        };
        let slice = MeshSlice::from_gateway_config(&config, request);
        assert!(
            slice.local_ingress_listeners.is_empty(),
            "dry-run must not resolve ingress listeners"
        );
        assert_eq!(
            slice.declared_ingress_http_ports, 0,
            "dry-run materializes no ingress, so the declared port count is 0 (no router \
             ambiguity, and the status writer reports ingress_modeled=0)"
        );
    }

    /// Codex round-4 P2: the DECLARED HTTP-family port count counts DISTINCT
    /// HTTP-family listener ports (resolvable or not) and EXCLUDES non-HTTP-family
    /// entries (deferred raw-TCP, never an HTTP route) and duplicate ports. This
    /// pins the exact boundary so the router's fail-closed ambiguity is neither
    /// over- nor under-counted.
    #[test]
    fn sidecar_ingress_declared_count_excludes_non_http_and_dedups_ports() {
        let spiffe = "spiffe://cluster.local/ns/alpha/sa/reviews";
        let mut reviews_wl = make_workload(
            "alpha",
            "reviews",
            HashMap::from([("app".to_string(), "reviews".to_string())]),
        );
        reviews_wl.spiffe_id = SpiffeId::new(spiffe).unwrap();
        let mut sidecar = make_sidecar(
            "reviews-sc",
            "alpha",
            Some(WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "reviews".to_string())]),
                namespace: Some("alpha".to_string()),
            }),
            vec![vec!["./checkout"]],
        );
        sidecar.ingress = vec![
            // HTTP, resolves → declared + resolved.
            MeshSidecarIngress {
                port: 8080,
                protocol: AppProtocol::Http,
                name: None,
                bind: None,
                default_endpoint: "127.0.0.1:5000".to_string(),
            },
            // HTTP-family (gRPC) but unroutable endpoint → declared, NOT resolved.
            MeshSidecarIngress {
                port: 8443,
                protocol: AppProtocol::Grpc,
                name: None,
                bind: None,
                default_endpoint: "unix:///var/run/grpc.sock".to_string(),
            },
            // Duplicate of the first listener port → does NOT add a distinct port.
            MeshSidecarIngress {
                port: 8080,
                protocol: AppProtocol::Http2,
                name: None,
                bind: None,
                default_endpoint: "127.0.0.1:5001".to_string(),
            },
            // Non-HTTP-family (raw TCP) → deferred, NOT counted as a declared
            // HTTP-family port.
            MeshSidecarIngress {
                port: 9000,
                protocol: AppProtocol::Tcp,
                name: None,
                bind: None,
                default_endpoint: "127.0.0.1:6000".to_string(),
            },
            // Zero port → no routable target, NOT counted.
            MeshSidecarIngress {
                port: 0,
                protocol: AppProtocol::Http,
                name: None,
                bind: None,
                default_endpoint: "127.0.0.1:7000".to_string(),
            },
        ];
        let mesh = MeshConfig {
            sidecars: vec![sidecar],
            workloads: vec![reviews_wl],
            services: vec![make_service("alpha", "reviews")],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let request = MeshSliceRequest {
            workload_spiffe_id: Some(spiffe.to_string()),
            ..slice_request_enforced_with_labels(
                "alpha",
                BTreeMap::from([("app".to_string(), "reviews".to_string())]),
            )
        };
        let slice = MeshSlice::from_gateway_config(&config, request);

        // Resolved: only the routable HTTP listener on 8080.
        assert_eq!(
            slice.local_ingress_listeners.len(),
            1,
            "only the routable HTTP listener resolves"
        );
        // Declared HTTP-family ports: {8080, 8443} = 2. The duplicate 8080, the
        // raw-TCP 9000, and the zero-port entry are excluded.
        assert_eq!(
            slice.declared_ingress_http_ports, 2,
            "distinct HTTP-family ports 8080 and 8443 are declared; the duplicate 8080, \
             the raw-TCP 9000, and the zero-port entry must not inflate the count"
        );
    }

    #[test]
    fn sidecar_narrowing_filters_services_and_destination_rules() {
        // MeshService and MeshDestinationRule are filtered too.
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["./reviews"]],
            )],
            services: vec![
                make_service("alpha", "reviews"),
                make_service("alpha", "checkout"),
            ],
            destination_rules: vec![
                MeshDestinationRule {
                    name: "reviews-dr".into(),
                    namespace: "alpha".into(),
                    host: "reviews".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
                MeshDestinationRule {
                    name: "checkout-dr".into(),
                    namespace: "alpha".into(),
                    host: "checkout".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.services.len(), 1);
        assert_eq!(slice.services[0].name, "reviews");
        assert_eq!(slice.destination_rules.len(), 1);
        assert_eq!(slice.destination_rules[0].name, "reviews-dr");
    }

    #[test]
    fn sidecar_identity_narrowing_filters_to_admitted_service_workloads() {
        let reviews = make_workload("alpha", "reviews", HashMap::new());
        let checkout = make_workload("alpha", "checkout", HashMap::new());
        let payments = make_workload("alpha", "payments", HashMap::new());
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["./reviews"]],
            )],
            services: vec![
                make_service_with_workload_refs(
                    "alpha",
                    "reviews",
                    vec![reviews.spiffe_id.clone(), checkout.spiffe_id.clone()],
                ),
                make_service_with_workload_refs(
                    "alpha",
                    "payments",
                    vec![payments.spiffe_id.clone()],
                ),
            ],
            workloads: vec![reviews.clone(), checkout.clone(), payments],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(
            &config,
            slice_request_enforced_with_identity_narrowing("alpha"),
        );

        assert_eq!(slice.services.len(), 1);
        assert_eq!(slice.services[0].name, "reviews");
        let identities: Vec<_> = slice
            .workloads
            .iter()
            .map(|workload| workload.spiffe_id.as_str())
            .collect();
        assert_eq!(identities, vec![reviews.spiffe_id.as_str()]);
        assert!(
            !slice
                .workloads
                .iter()
                .any(|workload| workload.spiffe_id == checkout.spiffe_id),
            "workloads from non-admitted services must not be retained even if an admitted service references their SPIFFE ID"
        );
    }

    #[test]
    fn sidecar_identity_narrowing_drops_non_admitted_workloads_with_same_spiffe_id() {
        let mut reviews = make_workload("alpha", "reviews", HashMap::new());
        let mut checkout = make_workload("alpha", "checkout", HashMap::new());
        let shared = reviews.spiffe_id.clone();
        checkout.spiffe_id = shared.clone();
        reviews.addresses = vec!["10.10.0.10".into()];
        checkout.addresses = vec!["10.10.0.20".into()];
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["./reviews"]],
            )],
            services: vec![
                make_service_with_workload_refs("alpha", "reviews", vec![shared]),
                make_service_with_workload_refs(
                    "alpha",
                    "checkout",
                    vec![checkout.spiffe_id.clone()],
                ),
            ],
            workloads: vec![reviews.clone(), checkout.clone()],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(
            &config,
            slice_request_enforced_with_identity_narrowing("alpha"),
        );

        assert_eq!(slice.services.len(), 1);
        assert_eq!(slice.services[0].name, "reviews");
        assert_eq!(slice.workloads.len(), 1);
        assert_eq!(slice.workloads[0].service_name, "reviews");
        assert_eq!(slice.workloads[0].addresses, vec!["10.10.0.10"]);
    }

    #[test]
    fn sidecar_identity_narrowing_is_independently_flag_gated() {
        let reviews = make_workload("alpha", "reviews", HashMap::new());
        let payments = make_workload("alpha", "payments", HashMap::new());
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["./reviews"]],
            )],
            services: vec![
                make_service_with_workload_refs(
                    "alpha",
                    "reviews",
                    vec![reviews.spiffe_id.clone()],
                ),
                make_service_with_workload_refs(
                    "alpha",
                    "payments",
                    vec![payments.spiffe_id.clone()],
                ),
            ],
            workloads: vec![reviews, payments],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));

        assert_eq!(slice.services.len(), 1);
        assert_eq!(
            slice.workloads.len(),
            2,
            "FERRUM_MESH_SIDECAR_IDENTITY_NARROWING=false keeps the legacy workload list"
        );
    }

    #[test]
    fn sidecar_identity_narrowing_requires_sidecar_egress_enforcement() {
        let reviews = make_workload("alpha", "reviews", HashMap::new());
        let payments = make_workload("alpha", "payments", HashMap::new());
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["./reviews"]],
            )],
            services: vec![
                make_service_with_workload_refs(
                    "alpha",
                    "reviews",
                    vec![reviews.spiffe_id.clone()],
                ),
                make_service_with_workload_refs(
                    "alpha",
                    "payments",
                    vec![payments.spiffe_id.clone()],
                ),
            ],
            workloads: vec![reviews, payments],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice =
            MeshSlice::from_gateway_config(&config, slice_request_identity_narrowing_only("alpha"));

        assert_eq!(
            slice.services.len(),
            2,
            "identity narrowing alone must not enable sidecar egress narrowing"
        );
        assert_eq!(
            slice.workloads.len(),
            2,
            "FERRUM_MESH_SIDECAR_IDENTITY_NARROWING=true is a no-op until FERRUM_MESH_SIDECAR_ENFORCED=true"
        );
    }

    #[test]
    fn sidecar_identity_narrowing_drops_workloads_when_no_services_admitted() {
        let reviews = make_workload("alpha", "reviews", HashMap::new());
        let payments = make_workload("alpha", "payments", HashMap::new());
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar("default-sc", "alpha", None, vec![vec!["~/*"]])],
            services: vec![
                make_service_with_workload_refs(
                    "alpha",
                    "reviews",
                    vec![reviews.spiffe_id.clone()],
                ),
                make_service_with_workload_refs(
                    "alpha",
                    "payments",
                    vec![payments.spiffe_id.clone()],
                ),
            ],
            workloads: vec![reviews, payments],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(
            &config,
            slice_request_enforced_with_identity_narrowing("alpha"),
        );

        assert!(
            slice.services.is_empty(),
            "the Sidecar egress scope admits no services"
        );
        assert!(
            slice.workloads.is_empty(),
            "identity narrowing follows the empty admitted-service set"
        );
    }

    #[test]
    fn sidecar_identity_narrowing_drops_workloads_when_services_have_no_refs() {
        let reviews = make_workload("alpha", "reviews", HashMap::new());
        let payments = make_workload("alpha", "payments", HashMap::new());
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["./reviews"]],
            )],
            services: vec![
                make_service("alpha", "reviews"),
                make_service_with_workload_refs(
                    "alpha",
                    "payments",
                    vec![payments.spiffe_id.clone()],
                ),
            ],
            workloads: vec![reviews, payments],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(
            &config,
            slice_request_enforced_with_identity_narrowing("alpha"),
        );

        assert_eq!(slice.services.len(), 1);
        assert_eq!(slice.services[0].name, "reviews");
        assert!(
            slice.workloads.is_empty(),
            "admitted services without workload refs yield an empty reachable identity set"
        );
    }

    #[test]
    fn sidecar_identity_narrowing_preserves_trust_bundles_for_inbound_mtls() {
        let reviews = make_workload("alpha", "reviews", HashMap::new());
        let filtered = make_workload("alpha", "filtered", HashMap::new());
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["./reviews"]],
            )],
            services: vec![make_service_with_workload_refs(
                "alpha",
                "reviews",
                vec![reviews.spiffe_id.clone()],
            )],
            workloads: vec![reviews, filtered.clone()],
            trust_bundles: Some(make_trust_bundle_set()),
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(
            &config,
            slice_request_enforced_with_identity_narrowing("alpha"),
        );

        assert!(
            !slice
                .workloads
                .iter()
                .any(|workload| workload.spiffe_id == filtered.spiffe_id),
            "identity narrowing should remove workloads not referenced by admitted services"
        );
        assert!(
            slice.trust_bundles.is_some(),
            "inbound mTLS peer validation uses trust bundles, so narrowing workloads must not drop them"
        );
    }

    #[test]
    fn sidecar_narrowing_filters_service_ports_by_egress_port() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar_with_ports(
                "ports-sc",
                "alpha",
                None,
                vec![
                    (vec!["./reviews"], Some(8080)),
                    (vec!["*/api.example.com"], Some(8443)),
                ],
            )],
            services: vec![make_service_with_ports("alpha", "reviews", &[80, 8080])],
            service_entries: vec![make_se_with_host_and_ports(
                "api",
                "alpha",
                "api.example.com",
                &[443, 8443],
                vec!["*".into()],
            )],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.services.len(), 1);
        assert_eq!(port_numbers(&slice.services[0].ports), vec![8080]);
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(port_numbers(&slice.service_entries[0].ports), vec![8443]);
    }

    #[test]
    fn sidecar_narrowing_preserves_service_entry_host_port_pairs() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar_with_ports(
                "ports-sc",
                "alpha",
                None,
                vec![
                    (vec!["*/api.example.com"], Some(443)),
                    (vec!["*/db.example.com"], Some(5432)),
                ],
            )],
            service_entries: vec![ServiceEntry {
                name: "external".into(),
                namespace: "alpha".into(),
                hosts: vec!["api.example.com".into(), "db.example.com".into()],
                endpoints: Vec::new(),
                resolution: crate::modes::mesh::config::Resolution::None,
                location: ServiceEntryLocation::MeshExternal,
                ports: vec![
                    ServicePort {
                        port: 443,
                        protocol: AppProtocol::Http2,
                        name: None,
                        target_port: None,
                    },
                    ServicePort {
                        port: 5432,
                        protocol: AppProtocol::Tcp,
                        name: None,
                        target_port: None,
                    },
                ],
                export_to: vec!["*".into()],
                workload_selector: None,
            }],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));

        let mut ports_by_host = BTreeMap::new();
        for entry in &slice.service_entries {
            assert_eq!(entry.hosts.len(), 1);
            ports_by_host.insert(entry.hosts[0].as_str(), port_numbers(&entry.ports));
        }
        assert_eq!(ports_by_host.get("api.example.com"), Some(&vec![443]));
        assert_eq!(ports_by_host.get("db.example.com"), Some(&vec![5432]));
    }

    #[test]
    fn sidecar_narrowing_drops_service_when_all_ports_filtered_out() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar_with_ports(
                "ports-sc",
                "alpha",
                None,
                vec![(vec!["./reviews"], Some(9090))],
            )],
            services: vec![make_service_with_ports("alpha", "reviews", &[80, 8080])],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert!(slice.services.is_empty());
    }

    #[test]
    fn sidecar_narrowing_keeps_host_admitted_service_with_no_declared_ports() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "host-sc",
                "alpha",
                None,
                vec![vec!["./reviews"]],
            )],
            services: vec![make_service_with_ports("alpha", "reviews", &[])],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.services.len(), 1);
        assert!(slice.services[0].ports.is_empty());
    }

    #[test]
    fn sidecar_narrowing_keeps_host_admitted_service_entry_with_no_declared_ports() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "host-sc",
                "alpha",
                None,
                vec![vec!["*/api.example.com"]],
            )],
            service_entries: vec![make_se_with_host_and_ports(
                "api",
                "alpha",
                "api.example.com",
                &[],
                vec!["*".into()],
            )],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.service_entries.len(), 1);
        assert!(slice.service_entries[0].ports.is_empty());
    }

    #[test]
    fn sidecar_narrowing_keeps_all_ports_when_egress_has_no_port() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "ports-sc",
                "alpha",
                None,
                vec![vec!["./reviews"]],
            )],
            services: vec![make_service_with_ports("alpha", "reviews", &[80, 8080])],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.services.len(), 1);
        assert_eq!(port_numbers(&slice.services[0].ports), vec![80, 8080]);
    }

    #[test]
    fn sidecar_narrowing_unions_ports_across_egress_entries() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar_with_ports(
                "ports-sc",
                "alpha",
                None,
                vec![
                    (vec!["./reviews"], Some(8080)),
                    (vec!["./reviews"], Some(80)),
                ],
            )],
            services: vec![make_service_with_ports(
                "alpha",
                "reviews",
                &[80, 8080, 9090],
            )],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.services.len(), 1);
        assert_eq!(port_numbers(&slice.services[0].ports), vec![80, 8080]);
    }

    #[test]
    fn sidecar_narrowing_specific_port_overrides_portless_host_entry_for_that_port() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar_with_ports(
                "ports-sc",
                "alpha",
                None,
                vec![(vec!["./*"], None), (vec!["./payments"], Some(443))],
            )],
            services: vec![
                make_service_with_ports("alpha", "reviews", &[80, 443]),
                make_service_with_ports("alpha", "payments", &[443]),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));

        let reviews = slice
            .services
            .iter()
            .find(|service| service.name == "reviews")
            .expect("reviews service");
        assert_eq!(
            port_numbers(&reviews.ports),
            vec![80],
            "portless ./ * should not admit 443 when a specific 443 listener exists"
        );
        let payments = slice
            .services
            .iter()
            .find(|service| service.name == "payments")
            .expect("payments service");
        assert_eq!(port_numbers(&payments.ports), vec![443]);
    }

    #[test]
    fn sidecar_narrowing_destination_rules_ignore_port() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar_with_ports(
                "ports-sc",
                "alpha",
                None,
                vec![(vec!["./reviews"], Some(9090))],
            )],
            services: vec![make_service_with_ports("alpha", "reviews", &[80])],
            destination_rules: vec![MeshDestinationRule {
                name: "reviews-dr".into(),
                namespace: "alpha".into(),
                host: "reviews".into(),
                traffic_policy: None,
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert!(slice.services.is_empty());
        assert_eq!(slice.destination_rules.len(), 1);
        assert_eq!(slice.destination_rules[0].name, "reviews-dr");
    }

    #[test]
    fn sidecar_narrowing_matches_mesh_service_fqdn_alias() {
        // Operators commonly scope Kubernetes Services by FQDN in Sidecar
        // hosts. MeshService stores only name + namespace, so the slice
        // builder must synthesize DNS aliases before matching.
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["./reviews.alpha.svc.cluster.local"]],
            )],
            services: vec![
                make_service("alpha", "reviews"),
                make_service("alpha", "checkout"),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.services.len(), 1);
        assert_eq!(slice.services[0].name, "reviews");
    }

    #[test]
    fn sidecar_narrowing_uses_cluster_domain_for_mesh_service_fqdn_alias() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["./reviews.alpha.svc.corp.local"]],
            )],
            services: vec![
                make_service("alpha", "reviews"),
                make_service("alpha", "checkout"),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let request = slice_request_enforced("alpha").with_cluster_domain("corp.local".to_string());
        let slice = MeshSlice::from_gateway_config(&config, request);
        assert_eq!(slice.services.len(), 1);
        assert_eq!(slice.services[0].name, "reviews");
    }

    #[test]
    fn sidecar_narrowing_matches_destination_rule_short_host_against_fqdn_scope() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["./reviews.alpha.svc.cluster.local"]],
            )],
            destination_rules: vec![
                MeshDestinationRule {
                    name: "reviews-dr".into(),
                    namespace: "alpha".into(),
                    host: "reviews".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
                MeshDestinationRule {
                    name: "checkout-dr".into(),
                    namespace: "alpha".into(),
                    host: "checkout".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.destination_rules.len(), 1);
        assert_eq!(slice.destination_rules[0].name, "reviews-dr");
    }

    #[test]
    fn sidecar_narrowing_matches_destination_rule_fqdn_host_against_short_scope() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["./reviews"]],
            )],
            services: vec![
                make_service("alpha", "reviews"),
                make_service("alpha", "checkout"),
            ],
            destination_rules: vec![
                MeshDestinationRule {
                    name: "reviews-dr".into(),
                    namespace: "alpha".into(),
                    host: "reviews.alpha.svc.cluster.local".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
                MeshDestinationRule {
                    name: "checkout-dr".into(),
                    namespace: "alpha".into(),
                    host: "checkout.alpha.svc.cluster.local".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.destination_rules.len(), 1);
        assert_eq!(slice.destination_rules[0].name, "reviews-dr");
    }

    #[test]
    fn sidecar_narrowing_matches_destination_rule_target_namespace() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["beta/*"]],
            )],
            services: vec![make_service("beta", "reviews")],
            destination_rules: vec![
                MeshDestinationRule {
                    name: "beta-reviews-dr".into(),
                    namespace: "alpha".into(),
                    host: "reviews.beta.svc.cluster.local".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
                MeshDestinationRule {
                    name: "gamma-checkout-dr".into(),
                    namespace: "alpha".into(),
                    host: "checkout.gamma.svc.cluster.local".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.destination_rules.len(), 1);
        assert_eq!(slice.destination_rules[0].name, "beta-reviews-dr");
    }

    #[test]
    fn sidecar_narrowing_infers_destination_rule_fqdn_namespace_without_service_registry() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["beta/*"]],
            )],
            destination_rules: vec![MeshDestinationRule {
                name: "beta-reviews-dr".into(),
                namespace: "alpha".into(),
                host: "reviews.beta.svc.cluster.local".into(),
                traffic_policy: None,
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.destination_rules.len(), 1);
        assert_eq!(slice.destination_rules[0].name, "beta-reviews-dr");
    }

    #[test]
    fn sidecar_narrowing_matches_destination_rule_namespace_qualified_host() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["beta/*"]],
            )],
            services: vec![make_service("beta", "reviews")],
            destination_rules: vec![
                MeshDestinationRule {
                    name: "beta-reviews-dr".into(),
                    namespace: "alpha".into(),
                    host: "reviews.beta".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
                MeshDestinationRule {
                    name: "gamma-checkout-dr".into(),
                    namespace: "alpha".into(),
                    host: "checkout.gamma".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.destination_rules.len(), 1);
        assert_eq!(slice.destination_rules[0].name, "beta-reviews-dr");
    }

    #[test]
    fn sidecar_narrowing_keeps_external_two_label_destination_rule_literal() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["./example.com"]],
            )],
            services: vec![make_service("com", "unrelated")],
            destination_rules: vec![MeshDestinationRule {
                name: "external-dr".into(),
                namespace: "alpha".into(),
                host: "example.com".into(),
                traffic_policy: None,
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.destination_rules.len(), 1);
        assert_eq!(slice.destination_rules[0].name, "external-dr");
    }

    #[test]
    fn sidecar_narrowing_keeps_long_external_destination_rule_literal() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["./reviews.alpha.external.com"]],
            )],
            services: vec![make_service("alpha", "reviews")],
            destination_rules: vec![MeshDestinationRule {
                name: "external-dr".into(),
                namespace: "alpha".into(),
                host: "reviews.alpha.external.com".into(),
                traffic_policy: None,
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.destination_rules.len(), 1);
        assert_eq!(slice.destination_rules[0].name, "external-dr");
    }

    #[test]
    fn sidecar_narrowing_keeps_external_dot_svc_destination_rule_literal() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["./api.foo.svc"]],
            )],
            services: vec![make_service("alpha", "reviews")],
            service_entries: vec![make_se_with_host(
                "api-foo",
                "alpha",
                "api.foo.svc",
                vec!["*".into()],
            )],
            destination_rules: vec![MeshDestinationRule {
                name: "external-dr".into(),
                namespace: "alpha".into(),
                host: "api.foo.svc".into(),
                traffic_policy: None,
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.destination_rules.len(), 1);
        assert_eq!(slice.destination_rules[0].name, "external-dr");
    }

    #[test]
    fn sidecar_narrowing_ignores_invisible_service_entry_host_for_destination_rule_scope() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["beta/*"]],
            )],
            service_entries: vec![make_se_with_host(
                "private-foo",
                "beta",
                "foo.beta.svc",
                vec![".".into()],
            )],
            destination_rules: vec![MeshDestinationRule {
                name: "beta-foo-dr".into(),
                namespace: "alpha".into(),
                host: "foo.beta.svc".into(),
                traffic_policy: None,
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.destination_rules.len(), 1);
        assert_eq!(slice.destination_rules[0].name, "beta-foo-dr");
    }

    #[test]
    fn sidecar_narrowing_rejects_destination_rule_from_unrelated_namespace() {
        // Istio DestinationRule lookup namespaces are {client, target
        // service, root}. A DR declared in `gamma` targeting
        // `reviews.beta` must NOT be imported into an `alpha` workload's
        // slice even if its Sidecar admits `beta/*` — `gamma` is none of
        // the lookup namespaces.
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["beta/*"]],
            )],
            services: vec![make_service("beta", "reviews")],
            destination_rules: vec![MeshDestinationRule {
                name: "cross-ns-dr".into(),
                namespace: "gamma".into(),
                host: "reviews.beta.svc.cluster.local".into(),
                traffic_policy: None,
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert!(slice.destination_rules.is_empty());
    }

    #[test]
    fn sidecar_narrowing_admits_destination_rule_from_target_service_namespace() {
        // A DR declared in the target service's namespace (`beta`) must
        // still be admitted alongside one declared in the client
        // namespace (`alpha`); a DR declared in an unrelated namespace
        // (`gamma`) targeting the same host must be filtered out.
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "default-sc",
                "alpha",
                None,
                vec![vec!["beta/*"]],
            )],
            services: vec![make_service("beta", "reviews")],
            destination_rules: vec![
                MeshDestinationRule {
                    name: "from-client-ns".into(),
                    namespace: "alpha".into(),
                    host: "reviews.beta.svc.cluster.local".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
                MeshDestinationRule {
                    name: "from-target-ns".into(),
                    namespace: "beta".into(),
                    host: "reviews.beta.svc.cluster.local".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
                MeshDestinationRule {
                    name: "from-unrelated-ns".into(),
                    namespace: "gamma".into(),
                    host: "reviews.beta.svc.cluster.local".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        let names: BTreeSet<&str> = slice
            .destination_rules
            .iter()
            .map(|dr| dr.name.as_str())
            .collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains("from-client-ns"));
        assert!(names.contains("from-target-ns"));
    }

    #[test]
    fn sidecar_resolution_prefers_workload_scoped_over_namespace_default() {
        // A workload that matches both a workload-scoped and a namespace-
        // default Sidecar should get the workload-scoped one.
        let mesh = MeshConfig {
            sidecars: vec![
                // Namespace default — admits everything.
                make_sidecar("ns-default", "alpha", None, vec![vec!["*/*"]]),
                // Workload-scoped — admits only `reviews`.
                make_sidecar(
                    "frontend-only",
                    "alpha",
                    Some(WorkloadSelector {
                        labels: HashMap::from([("app".into(), "frontend".into())]),
                        namespace: None,
                    }),
                    vec![vec!["./reviews.alpha.svc.cluster.local"]],
                ),
            ],
            service_entries: vec![
                make_se_with_host(
                    "reviews",
                    "alpha",
                    "reviews.alpha.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "other",
                    "alpha",
                    "other.alpha.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let labels = BTreeMap::from([("app".into(), "frontend".into())]);
        let slice = MeshSlice::from_gateway_config(
            &config,
            slice_request_enforced_with_labels("alpha", labels),
        );
        assert_eq!(
            slice.service_entries.len(),
            1,
            "workload-scoped sidecar should win over namespace-default"
        );
        assert_eq!(slice.service_entries[0].name, "reviews");
    }

    #[test]
    fn sidecar_omitted_egress_inherits_namespace_default_scope() {
        let mesh = MeshConfig {
            sidecars: vec![
                make_sidecar(
                    "ns-default",
                    "alpha",
                    None,
                    vec![vec!["./reviews.alpha.svc.cluster.local"]],
                ),
                make_inheriting_sidecar(
                    "frontend-ingress-only",
                    "alpha",
                    WorkloadSelector {
                        labels: HashMap::from([("app".into(), "frontend".into())]),
                        namespace: Some("alpha".into()),
                    },
                ),
            ],
            service_entries: vec![
                make_se_with_host(
                    "reviews",
                    "alpha",
                    "reviews.alpha.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "checkout",
                    "alpha",
                    "checkout.alpha.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let labels = BTreeMap::from([("app".into(), "frontend".into())]);
        let slice = MeshSlice::from_gateway_config(
            &config,
            slice_request_enforced_with_labels("alpha", labels),
        );
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "reviews");
    }

    #[test]
    fn sidecar_omitted_egress_without_namespace_default_is_noop() {
        let mesh = MeshConfig {
            sidecars: vec![make_inheriting_sidecar(
                "frontend-ingress-only",
                "alpha",
                WorkloadSelector {
                    labels: HashMap::from([("app".into(), "frontend".into())]),
                    namespace: Some("alpha".into()),
                },
            )],
            service_entries: vec![
                make_se_with_host(
                    "reviews",
                    "alpha",
                    "reviews.alpha.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "checkout",
                    "alpha",
                    "checkout.alpha.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let labels = BTreeMap::from([("app".into(), "frontend".into())]);
        let slice = MeshSlice::from_gateway_config(
            &config,
            slice_request_enforced_with_labels("alpha", labels),
        );
        assert_eq!(slice.service_entries.len(), 2);
    }

    #[test]
    fn sidecar_root_namespace_default_applies_when_namespace_has_no_sidecar() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "mesh-default",
                "istio-system",
                None,
                vec![vec!["beta/*"]],
            )],
            service_entries: vec![
                make_se_with_host(
                    "reviews-beta",
                    "beta",
                    "reviews.beta.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "payments-gamma",
                    "gamma",
                    "payments.gamma.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "reviews-beta");
    }

    #[test]
    fn sidecar_root_namespace_default_same_namespace_host_uses_workload_namespace() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "mesh-default",
                "istio-system",
                None,
                vec![vec!["./*"]],
            )],
            service_entries: vec![
                make_se_with_host(
                    "reviews-alpha",
                    "alpha",
                    "reviews.alpha.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "control-root",
                    "istio-system",
                    "control.istio-system.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));

        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "reviews-alpha");
    }

    #[test]
    fn sidecar_root_namespace_explicit_mesh_wide_selector_applies_across_namespaces() {
        let mesh = MeshConfig {
            sidecars: vec![
                make_sidecar("namespace-default", "alpha", None, vec![vec!["gamma/*"]]),
                make_sidecar(
                    "mesh-frontend",
                    "istio-system",
                    Some(WorkloadSelector {
                        labels: HashMap::from([("app".into(), "frontend".into())]),
                        namespace: None,
                    }),
                    vec![vec!["beta/*"]],
                ),
            ],
            service_entries: vec![
                make_se_with_host(
                    "reviews-beta",
                    "beta",
                    "reviews.beta.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "payments-gamma",
                    "gamma",
                    "payments.gamma.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let labels = BTreeMap::from([("app".into(), "frontend".into())]);
        let slice = MeshSlice::from_gateway_config(
            &config,
            slice_request_enforced_with_labels("alpha", labels),
        );
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "reviews-beta");
    }

    #[test]
    fn sidecar_root_namespace_namespaced_selector_does_not_apply_across_namespaces() {
        let mesh = MeshConfig {
            sidecars: vec![
                make_sidecar("namespace-default", "alpha", None, vec![vec!["gamma/*"]]),
                make_sidecar(
                    "mesh-frontend",
                    "istio-system",
                    Some(WorkloadSelector {
                        labels: HashMap::from([("app".into(), "frontend".into())]),
                        namespace: Some("istio-system".into()),
                    }),
                    vec![vec!["beta/*"]],
                ),
            ],
            service_entries: vec![
                make_se_with_host(
                    "reviews-beta",
                    "beta",
                    "reviews.beta.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "payments-gamma",
                    "gamma",
                    "payments.gamma.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let labels = BTreeMap::from([("app".into(), "frontend".into())]);
        let slice = MeshSlice::from_gateway_config(
            &config,
            slice_request_enforced_with_labels("alpha", labels),
        );
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "payments-gamma");
    }

    #[test]
    fn sidecar_namespace_default_wins_over_root_namespace_default() {
        let mesh = MeshConfig {
            sidecars: vec![
                make_sidecar("mesh-default", "istio-system", None, vec![vec!["beta/*"]]),
                make_sidecar("namespace-default", "alpha", None, vec![vec!["gamma/*"]]),
            ],
            service_entries: vec![
                make_se_with_host(
                    "reviews-beta",
                    "beta",
                    "reviews.beta.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "payments-gamma",
                    "gamma",
                    "payments.gamma.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "payments-gamma");
    }

    #[test]
    fn sidecar_namespace_default_with_omitted_egress_falls_back_to_root_default() {
        let mesh = MeshConfig {
            sidecars: vec![
                make_sidecar("mesh-default", "istio-system", None, vec![vec!["beta/*"]]),
                MeshSidecar {
                    name: "namespace-default".into(),
                    namespace: "alpha".into(),
                    workload_selector: None,
                    egress_inherits_defaults: true,
                    egress: Vec::new(),
                    ingress_declared: false,
                    ingress: Vec::new(),
                    outbound_traffic_policy: None,
                },
            ],
            service_entries: vec![
                make_se_with_host(
                    "reviews-alpha",
                    "alpha",
                    "reviews.alpha.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "reviews-beta",
                    "beta",
                    "reviews.beta.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        let names: BTreeSet<&str> = slice
            .service_entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, BTreeSet::from(["reviews-beta"]));
    }

    #[test]
    fn sidecar_workload_scoped_inherits_root_default_when_namespace_default_absent() {
        let mesh = MeshConfig {
            sidecars: vec![
                make_sidecar("mesh-default", "istio-system", None, vec![vec!["beta/*"]]),
                make_inheriting_sidecar(
                    "frontend-ingress-only",
                    "alpha",
                    WorkloadSelector {
                        labels: HashMap::from([("app".into(), "frontend".into())]),
                        namespace: Some("alpha".into()),
                    },
                ),
            ],
            service_entries: vec![
                make_se_with_host(
                    "reviews-beta",
                    "beta",
                    "reviews.beta.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "payments-gamma",
                    "gamma",
                    "payments.gamma.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let labels = BTreeMap::from([("app".into(), "frontend".into())]);
        let slice = MeshSlice::from_gateway_config(
            &config,
            slice_request_enforced_with_labels("alpha", labels),
        );
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "reviews-beta");
    }

    #[test]
    fn sidecar_workload_scoped_with_inheriting_root_default_is_noop() {
        let mesh = MeshConfig {
            sidecars: vec![
                MeshSidecar {
                    name: "mesh-default".into(),
                    namespace: "istio-system".into(),
                    workload_selector: None,
                    egress_inherits_defaults: true,
                    egress: Vec::new(),
                    ingress_declared: false,
                    ingress: Vec::new(),
                    outbound_traffic_policy: None,
                },
                make_inheriting_sidecar(
                    "frontend-ingress-only",
                    "alpha",
                    WorkloadSelector {
                        labels: HashMap::from([("app".into(), "frontend".into())]),
                        namespace: Some("alpha".into()),
                    },
                ),
            ],
            service_entries: vec![
                make_se_with_host(
                    "reviews-beta",
                    "beta",
                    "reviews.beta.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "payments-gamma",
                    "gamma",
                    "payments.gamma.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let labels = BTreeMap::from([("app".into(), "frontend".into())]);
        let slice = MeshSlice::from_gateway_config(
            &config,
            slice_request_enforced_with_labels("alpha", labels),
        );
        let names: BTreeSet<&str> = slice
            .service_entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, BTreeSet::from(["payments-gamma", "reviews-beta"]));
    }

    #[test]
    fn sidecar_root_namespace_default_tiebreak_uses_ascii_smallest_name() {
        let mesh = MeshConfig {
            sidecars: vec![
                make_sidecar("b-default", "istio-system", None, vec![vec!["beta/*"]]),
                make_sidecar("a-default", "istio-system", None, vec![vec!["gamma/*"]]),
            ],
            service_entries: vec![
                make_se_with_host(
                    "reviews-beta",
                    "beta",
                    "reviews.beta.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "payments-gamma",
                    "gamma",
                    "payments.gamma.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "payments-gamma");
    }

    #[test]
    fn sidecar_root_namespace_default_uses_mesh_config_root_namespace() {
        let mesh = MeshConfig {
            istio_root_namespace: "istio-config".into(),
            sidecars: vec![make_sidecar(
                "mesh-default",
                "istio-config",
                None,
                vec![vec!["beta/*"]],
            )],
            service_entries: vec![
                make_se_with_host(
                    "reviews-beta",
                    "beta",
                    "reviews.beta.svc.cluster.local",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "payments-gamma",
                    "gamma",
                    "payments.gamma.svc.cluster.local",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "reviews-beta");
    }

    #[test]
    fn sidecar_with_empty_egress_blocks_everything() {
        // Native/file MeshSidecar with an explicit empty egress list trims all
        // egress config. Kubernetes omitted spec.egress sets
        // `egress_inherits_defaults` instead.
        let mesh = MeshConfig {
            sidecars: vec![MeshSidecar {
                name: "block-all".into(),
                namespace: "alpha".into(),
                workload_selector: None,
                egress_inherits_defaults: false,
                egress: Vec::new(),
                ingress_declared: false,
                ingress: Vec::new(),
                outbound_traffic_policy: None,
            }],
            service_entries: vec![make_se_with_host(
                "reviews",
                "alpha",
                "reviews.alpha.svc.cluster.local",
                vec!["*".into()],
            )],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert!(slice.service_entries.is_empty());
    }

    #[test]
    fn sidecar_no_namespace_pattern_trims_service_config() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar("trim-all", "alpha", None, vec![vec!["~/*"]])],
            services: vec![make_service("alpha", "reviews")],
            service_entries: vec![make_se_with_host(
                "reviews",
                "alpha",
                "reviews.alpha.svc.cluster.local",
                vec!["*".into()],
            )],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert!(slice.services.is_empty());
        assert!(slice.service_entries.is_empty());
    }

    #[test]
    fn sidecar_parse_host_pattern_round_trip() {
        assert_eq!(
            MeshSidecarEgress::parse_host_pattern("*/*"),
            SidecarHostPattern::AllowAll
        );
        assert_eq!(
            MeshSidecarEgress::parse_host_pattern("*/reviews"),
            SidecarHostPattern::AnyNamespaceHost { host: "reviews" }
        );
        assert_eq!(
            MeshSidecarEgress::parse_host_pattern("./reviews"),
            SidecarHostPattern::SameNamespaceHost { host: "reviews" }
        );
        assert_eq!(
            MeshSidecarEgress::parse_host_pattern("alpha/reviews"),
            SidecarHostPattern::NamespaceHost {
                namespace: "alpha",
                host: "reviews",
            }
        );
        assert_eq!(
            MeshSidecarEgress::parse_host_pattern("alpha/*"),
            SidecarHostPattern::NamespaceWildcard { namespace: "alpha" }
        );
        assert_eq!(
            MeshSidecarEgress::parse_host_pattern("~/*"),
            SidecarHostPattern::NamespaceWildcard { namespace: "~" }
        );
        assert_eq!(
            MeshSidecarEgress::parse_host_pattern("bare-host"),
            SidecarHostPattern::SameNamespaceHostBare { host: "bare-host" }
        );
    }

    // ── Wildcard host matching (Istio `*.foo.com` semantics) ────────────

    #[test]
    fn sidecar_host_pattern_matches_single_label_dns_wildcard() {
        // `*/*.foo.com` admits any single-label child of `foo.com` in any
        // namespace. Mirrors the canonical Istio Sidecar wildcard semantic.
        assert!(host_matches_pattern("*.foo.com", "bar.foo.com"));
        assert!(host_matches_pattern("*.foo.com", "baz.foo.com"));
        // Base domain itself does NOT match.
        assert!(!host_matches_pattern("*.foo.com", "foo.com"));
        // Multi-level subdomains do NOT match (single-label wildcard).
        assert!(!host_matches_pattern("*.foo.com", "a.b.foo.com"));
        // Unrelated host.
        assert!(!host_matches_pattern("*.foo.com", "foo.example.com"));
        // Empty prefix (just `.foo.com`) does NOT match.
        assert!(!host_matches_pattern("*.foo.com", ".foo.com"));
    }

    #[test]
    fn sidecar_host_pattern_matches_exact_string() {
        assert!(host_matches_pattern("reviews", "reviews"));
        assert!(host_matches_pattern(
            "reviews.alpha.svc.cluster.local",
            "reviews.alpha.svc.cluster.local"
        ));
        assert!(!host_matches_pattern("reviews", "checkout"));
    }

    #[test]
    fn sidecar_host_pattern_does_not_treat_bare_star_as_wildcard() {
        // A bare `*` is normally trapped by the higher-level pattern parser
        // (`*/*`, `namespace/*`); reaching the host predicate with `pattern
        // == "*"` is only possible via the `any_host_matches` fast-path.
        // `host_matches_pattern` itself stays strict — it must not silently
        // glob.
        assert!(!host_matches_pattern("*", "anything"));
    }

    #[test]
    fn sidecar_narrowing_admits_dns_wildcard_against_service_entry_host() {
        // `*/*.example.com` admits any single-label child of example.com.
        // Verifies wildcard matching threads through the full slice builder.
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "wildcard-sc",
                "alpha",
                None,
                vec![vec!["*/*.example.com"]],
            )],
            service_entries: vec![
                make_se_with_host("admit", "alpha", "api.example.com", vec!["*".into()]),
                make_se_with_host("reject-base", "alpha", "example.com", vec!["*".into()]),
                make_se_with_host(
                    "reject-deep",
                    "alpha",
                    "deep.api.example.com",
                    vec!["*".into()],
                ),
                make_se_with_host(
                    "reject-other",
                    "alpha",
                    "api.unrelated.com",
                    vec!["*".into()],
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(
            slice.service_entries.len(),
            1,
            "only api.example.com admitted"
        );
        assert_eq!(slice.service_entries[0].name, "admit");
    }

    #[test]
    fn sidecar_narrowing_dns_wildcard_in_namespace_scoped_pattern() {
        // `./` + wildcard host: `./*.example.com` admits wildcard hosts ONLY
        // in the sidecar's own namespace. Cross-namespace entries with the
        // same wildcard surface must NOT match.
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "ns-wildcard-sc",
                "alpha",
                None,
                vec![vec!["./*.example.com"]],
            )],
            service_entries: vec![
                make_se_with_host("alpha-hit", "alpha", "api.example.com", vec!["*".into()]),
                make_se_with_host("beta-miss", "beta", "api.example.com", vec!["*".into()]),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "alpha-hit");
    }

    #[test]
    fn sidecar_narrowing_dns_wildcard_combined_with_namespace_prefix() {
        // `production/*.example.com` admits wildcard hosts ONLY in the
        // explicitly named namespace, regardless of the sidecar's own
        // namespace.
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "explicit-ns-sc",
                "alpha",
                None,
                vec![vec!["production/*.example.com"]],
            )],
            service_entries: vec![
                make_se_with_host(
                    "production-hit",
                    "production",
                    "api.example.com",
                    vec!["*".into()],
                ),
                make_se_with_host("alpha-miss", "alpha", "api.example.com", vec!["*".into()]),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "production-hit");
    }

    #[test]
    fn sidecar_narrowing_multi_host_service_entry_any_match_admits() {
        // A ServiceEntry with multiple hosts: as long as ONE host matches the
        // egress pattern, the whole entry is admitted. Documented at the
        // sidecar_egress_includes_service rustdoc.
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "wildcard-sc",
                "alpha",
                None,
                vec![vec!["*/*.example.com"]],
            )],
            service_entries: vec![ServiceEntry {
                name: "multi-host".into(),
                namespace: "alpha".into(),
                hosts: vec!["api.example.com".into(), "unrelated.other.com".into()],
                endpoints: Vec::new(),
                resolution: crate::modes::mesh::config::Resolution::None,
                location: ServiceEntryLocation::MeshExternal,
                ports: vec![ServicePort {
                    port: 443,
                    protocol: AppProtocol::Http2,
                    name: None,
                    target_port: None,
                }],
                export_to: vec!["*".into()],
                workload_selector: None,
            }],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.service_entries.len(), 1);
    }

    #[test]
    fn sidecar_port_specific_egress_does_not_admit_portless_service_entry() {
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar_with_ports(
                "port-only",
                "alpha",
                None,
                vec![(vec!["./api.example.com"], Some(443))],
            )],
            service_entries: vec![make_se_with_host_and_ports(
                "api",
                "alpha",
                "api.example.com",
                &[],
                vec!["*".into()],
            )],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert!(
            slice.service_entries.is_empty(),
            "port-specific sidecar egress must not widen a portless ServiceEntry into any-port admission"
        );
    }

    #[test]
    fn sidecar_narrowing_multiple_egress_entries_evaluated_independently() {
        // Each `egress[]` entry is its own OR clause. A second entry must
        // admit a service that the first one rejects.
        let mesh = MeshConfig {
            sidecars: vec![MeshSidecar {
                name: "two-clauses".into(),
                namespace: "alpha".into(),
                workload_selector: None,
                egress_inherits_defaults: false,
                egress: vec![
                    MeshSidecarEgress {
                        hosts: vec!["./reviews".into()],
                        port: None,
                    },
                    MeshSidecarEgress {
                        hosts: vec!["beta/checkout".into()],
                        port: None,
                    },
                ],
                ingress_declared: false,
                ingress: Vec::new(),
                outbound_traffic_policy: None,
            }],
            services: vec![
                make_service("alpha", "reviews"),
                make_service("alpha", "other-alpha"),
            ],
            destination_rules: vec![MeshDestinationRule {
                name: "beta-checkout-dr".into(),
                namespace: "beta".into(),
                host: "checkout".into(),
                traffic_policy: None,
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.services.len(), 1);
        assert_eq!(slice.services[0].name, "reviews");
        assert_eq!(slice.destination_rules.len(), 1);
        assert_eq!(slice.destination_rules[0].name, "beta-checkout-dr");
    }

    #[test]
    fn sidecar_narrowing_admits_cross_namespace_services_and_destination_rules() {
        // `beta/*` should admit beta services and DestinationRules when Sidecar
        // enforcement is enabled. This mirrors ServiceEntry behavior and keeps
        // Istio namespace-scoped egress patterns from becoming silently inert.
        let mesh = MeshConfig {
            sidecars: vec![make_sidecar(
                "beta-egress",
                "alpha",
                None,
                vec![vec!["beta/*"]],
            )],
            services: vec![
                make_service("alpha", "reviews"),
                make_service("beta", "checkout"),
                make_service("gamma", "payments"),
            ],
            destination_rules: vec![
                MeshDestinationRule {
                    name: "alpha-reviews-dr".into(),
                    namespace: "alpha".into(),
                    host: "reviews".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
                MeshDestinationRule {
                    name: "beta-checkout-dr".into(),
                    namespace: "beta".into(),
                    host: "checkout".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
                MeshDestinationRule {
                    name: "gamma-payments-dr".into(),
                    namespace: "gamma".into(),
                    host: "payments".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(slice.services.len(), 1);
        assert_eq!(slice.services[0].namespace, "beta");
        assert_eq!(slice.services[0].name, "checkout");
        assert_eq!(slice.destination_rules.len(), 1);
        assert_eq!(slice.destination_rules[0].name, "beta-checkout-dr");
    }

    #[test]
    fn sidecar_outbound_traffic_policy_overrides_mesh_wide_even_without_enforcement() {
        // Sidecar.outboundTrafficPolicy is a security control: it applies even
        // when FERRUM_MESH_SIDECAR_ENFORCED is off (egress host narrowing stays
        // gated). A workload-scoped REGISTRY_ONLY Sidecar must win over mesh-wide
        // ALLOW_ANY and land on the slice for cold-path materialization.
        let mut mesh = MeshConfig {
            outbound_traffic_policy: Some(OutboundTrafficPolicy::AllowAny),
            sidecars: vec![MeshSidecar {
                name: "frontend".into(),
                namespace: "alpha".into(),
                workload_selector: Some(WorkloadSelector {
                    labels: HashMap::from([("app".into(), "frontend".into())]),
                    namespace: Some("alpha".into()),
                }),
                egress_inherits_defaults: true,
                egress: Vec::new(),
                ingress_declared: false,
                ingress: Vec::new(),
                outbound_traffic_policy: Some(OutboundTrafficPolicy::RegistryOnly),
            }],
            ..MeshConfig::default()
        };
        // Keep a namespace-default Sidecar without a policy so inheritance/precedence
        // cannot accidentally pick it for the policy field.
        mesh.sidecars.push(MeshSidecar {
            name: "namespace-default".into(),
            namespace: "alpha".into(),
            workload_selector: None,
            egress_inherits_defaults: false,
            egress: vec![MeshSidecarEgress {
                hosts: vec!["./*".into()],
                port: None,
            }],
            ingress_declared: false,
            ingress: Vec::new(),
            outbound_traffic_policy: None,
        });
        let config = config_with_mesh(mesh);
        let labels = BTreeMap::from([("app".into(), "frontend".into())]);
        let slice = MeshSlice::from_gateway_config(
            &config,
            MeshSliceRequest {
                namespace: "alpha".into(),
                labels,
                enforce_sidecar_egress: false,
                ..MeshSliceRequest::default()
            },
        );
        assert_eq!(
            slice.outbound_traffic_policy,
            Some(OutboundTrafficPolicy::RegistryOnly),
            "selected Sidecar REGISTRY_ONLY must override mesh-wide ALLOW_ANY"
        );
    }

    #[test]
    fn sidecar_omitted_outbound_traffic_policy_inherits_mesh_wide() {
        let mesh = MeshConfig {
            outbound_traffic_policy: Some(OutboundTrafficPolicy::RegistryOnly),
            sidecars: vec![MeshSidecar {
                name: "namespace-default".into(),
                namespace: "alpha".into(),
                workload_selector: None,
                egress_inherits_defaults: false,
                egress: vec![MeshSidecarEgress {
                    hosts: vec!["./*".into()],
                    port: None,
                }],
                ingress_declared: false,
                ingress: Vec::new(),
                outbound_traffic_policy: None,
            }],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(
            slice.outbound_traffic_policy,
            Some(OutboundTrafficPolicy::RegistryOnly),
            "omitted Sidecar outboundTrafficPolicy inherits MeshConfig"
        );
    }

    #[test]
    fn sidecar_outbound_traffic_policy_allow_any_overrides_mesh_registry_only() {
        let mesh = MeshConfig {
            outbound_traffic_policy: Some(OutboundTrafficPolicy::RegistryOnly),
            sidecars: vec![MeshSidecar {
                name: "namespace-default".into(),
                namespace: "alpha".into(),
                workload_selector: None,
                egress_inherits_defaults: false,
                egress: vec![MeshSidecarEgress {
                    hosts: vec!["./*".into()],
                    port: None,
                }],
                ingress_declared: false,
                ingress: Vec::new(),
                outbound_traffic_policy: Some(OutboundTrafficPolicy::AllowAny),
            }],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request_enforced("alpha"));
        assert_eq!(
            slice.outbound_traffic_policy,
            Some(OutboundTrafficPolicy::AllowAny),
            "Sidecar ALLOW_ANY must override mesh-wide REGISTRY_ONLY without widening unrelated policy"
        );
    }

    #[test]
    fn sidecar_outbound_traffic_policy_does_not_follow_egress_inherits_defaults() {
        // When a workload Sidecar omits egress (inherits defaults) but sets
        // outboundTrafficPolicy, the policy comes from the selected Sidecar —
        // not from the namespace-default Sidecar that supplies egress hosts.
        let mesh = MeshConfig {
            outbound_traffic_policy: Some(OutboundTrafficPolicy::AllowAny),
            sidecars: vec![
                MeshSidecar {
                    name: "namespace-default".into(),
                    namespace: "alpha".into(),
                    workload_selector: None,
                    egress_inherits_defaults: false,
                    egress: vec![MeshSidecarEgress {
                        hosts: vec!["./*".into()],
                        port: None,
                    }],
                    ingress_declared: false,
                    ingress: Vec::new(),
                    outbound_traffic_policy: Some(OutboundTrafficPolicy::AllowAny),
                },
                MeshSidecar {
                    name: "frontend".into(),
                    namespace: "alpha".into(),
                    workload_selector: Some(WorkloadSelector {
                        labels: HashMap::from([("app".into(), "frontend".into())]),
                        namespace: Some("alpha".into()),
                    }),
                    egress_inherits_defaults: true,
                    egress: Vec::new(),
                    ingress_declared: false,
                    ingress: Vec::new(),
                    outbound_traffic_policy: Some(OutboundTrafficPolicy::RegistryOnly),
                },
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let labels = BTreeMap::from([("app".into(), "frontend".into())]);
        let slice = MeshSlice::from_gateway_config(
            &config,
            slice_request_enforced_with_labels("alpha", labels),
        );
        assert_eq!(
            slice.outbound_traffic_policy,
            Some(OutboundTrafficPolicy::RegistryOnly),
            "selected Sidecar policy must not be replaced by the egress-inheritance donor"
        );
    }
}
