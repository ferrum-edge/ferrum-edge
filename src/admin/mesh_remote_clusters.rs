//! Response builder for `GET /mesh/remote-clusters` (F7.2).
//!
//! Operators previously inferred remote-cluster state only indirectly: a
//! healthy cross-cluster discovery shows up as a bump in
//! `GET /mesh/config-drift`'s workload/service `resources` counts, and a
//! stuck one shows up as those counts going flat — neither tells you *which*
//! remote cluster is contributing, nor distinguishes "configured but never
//! successfully polled" from "not configured at all". This endpoint surfaces
//! the data plane's own view of multicluster east-west discovery directly.
//!
//! Two views are returned, kept deliberately separate because they answer
//! different questions:
//!
//!   - `discovered`: the live
//!     [`crate::modes::mesh::multicluster::RemoteEndpointStore`] snapshot —
//!     remote clusters this DP has actually fetched endpoints from, keyed by
//!     cluster name, with per-cluster workload/service counts and the fetch
//!     timestamp + derived age. This is the authoritative "what is this DP
//!     merging into its local registry right now" answer. An empty map means
//!     discovery is disabled (`FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS`
//!     is `0`), no remote cluster is trust-eligible yet, or no poll has
//!     succeeded.
//!   - `configured`: the remote clusters declared in the **accepted** slice's
//!     `MultiClusterConfig` (name, trust domain, network, and whether a
//!     `control_plane_url` / `federation_endpoint` is set). A cluster that is
//!     `configured` but absent from `discovered` is the exact "I declared it
//!     but nothing is coming back" signal operators want — without it, a
//!     misconfigured / unreachable remote cluster is invisible.
//!
//! Like the other `/mesh/*` introspection endpoints, the handler in
//! `admin/mod.rs` returns `404` when the process is not in mesh mode (no mesh
//! runtime state wired), and the surface is JWT-authenticated. The payload is
//! a topology-shape summary — counts and provenance, never raw workload
//! addresses, SPIFFE IDs, or control-plane URLs — so the sensitive detail that
//! `/mesh/config-drift` keeps off `/metrics` stays off this surface too, while
//! the JWT still gates the topology shape it does reveal.
//!
//! See `docs/mesh.md` "Cross-Cluster Endpoint Discovery" for the operator
//! playbook.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::modes::mesh::config::{MultiClusterConfig, RemoteCluster, TrustBundleSet};
use crate::modes::mesh::federation::FederationSnapshot;
use crate::modes::mesh::multicluster::RemoteEndpointSnapshot;

const TRUST_SOURCE_POLLED: &str = "polled";
const TRUST_SOURCE_CONTROL_PLANE: &str = "control_plane";
const TRUST_SOURCE_LOCAL: &str = "local";
const TRUST_SOURCE_BLOCKED_PENDING_POLL: &str = "blocked_pending_poll";
const TRUST_SOURCE_NONE: &str = "none";

/// One remote cluster this DP has successfully fetched endpoints from. Counts
/// (not the endpoints themselves) are surfaced so the payload describes the
/// shape of cross-cluster discovery without re-exporting every workload
/// address / identity — mirroring `/mesh/config-drift`'s per-kind `resources`
/// counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredRemoteCluster {
    /// Operator-facing remote cluster name (the `RemoteEndpointSnapshot` key,
    /// validated unique). Repeated in the body so each entry is
    /// self-describing.
    pub cluster_name: String,
    /// SPIFFE trust domain the remote cluster's endpoints were ingested under.
    pub trust_domain: String,
    /// Istio network label of the remote cluster, used to default remote
    /// workload locality for multi-network routing. Absent when the remote
    /// cluster declares no network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Number of remote workloads merged into the local registry from this
    /// cluster.
    pub workload_count: usize,
    /// Number of remote services merged into the local registry from this
    /// cluster.
    pub service_count: usize,
    /// Unix timestamp (seconds) of the most recent successful poll of this
    /// cluster.
    pub fetched_at_unix_seconds: u64,
    /// `now - fetched_at_unix_seconds`, clamped to `0`. Operators alert on
    /// this exceeding a few poll intervals to spot a remote cluster whose
    /// discovery has wedged while keeping its last-good endpoints.
    pub age_seconds: u64,
}

/// One remote cluster declared in the accepted slice's `MultiClusterConfig`.
/// Reveals only the shape of the configuration — never the control-plane /
/// federation URLs themselves (those are surfaced as booleans), keeping
/// endpoint detail off the wire while still letting operators confirm a
/// cluster is configured for discovery (`control_plane_url`) and/or trust
/// federation (`federation_endpoint`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfiguredRemoteCluster {
    /// Operator-facing remote cluster name.
    pub cluster_name: String,
    /// SPIFFE trust domain declared for the remote cluster.
    pub trust_domain: String,
    /// Istio network label, when declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Whether a `control_plane_url` is configured — i.e. whether this cluster
    /// is a candidate for cross-cluster endpoint discovery at all. `false`
    /// means the cluster is federation-only and will never appear under
    /// `discovered`.
    pub control_plane_configured: bool,
    /// Whether a `federation_endpoint` is configured for SPIFFE trust-bundle
    /// exchange with this cluster.
    pub federation_endpoint_configured: bool,
    /// The JWT `aud` value this data plane mints into remote-discovery tokens
    /// for this cluster, derived from `cluster_name` (issue #2475). Present
    /// only when `control_plane_configured` is `true` — a federation-only
    /// cluster is never polled and mints no discovery token. This is derived
    /// configuration, not a credential: it names the target cluster and
    /// reveals nothing about the JWT secret. Operators use it to confirm the
    /// peer control plane's `FERRUM_MESH_CLUSTER_AUDIENCE` matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_audience: Option<String>,
    /// `true` when a cluster of this name is present in the live `discovered`
    /// map — a quick "is configured discovery actually returning anything?"
    /// flag so operators don't have to cross-reference the two lists by hand.
    pub discovered: bool,
    /// Whether this data plane has an active outbound trust bundle for the
    /// remote trust domain.
    pub outbound_trust_active: bool,
    /// Whether this data plane has an active inbound SPIFFE verifier that can
    /// authenticate peers from the remote trust domain.
    pub inbound_trust_active: bool,
    /// Source of the remote trust state: `polled`, `control_plane`, `local`,
    /// `blocked_pending_poll`, or `none`.
    pub trust_source: String,
    /// Unix timestamp (seconds) of the last successful polled bundle fetch when
    /// `trust_source` is `polled`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_bundle_fetched_at_unix_seconds: Option<u64>,
    /// `now - trust_bundle_fetched_at_unix_seconds`, clamped to `0`, when a
    /// polled bundle is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_bundle_age_seconds: Option<u64>,
}

/// Top-level response shape. The handler in `admin/mod.rs` is a thin wrapper
/// that stages [`MeshRemoteClustersInputs`] and serializes this struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshRemoteClustersResponse {
    /// `true` when cross-cluster endpoint discovery is enabled
    /// (`FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS > 0`). When
    /// `false`, `discovered` is always empty regardless of configuration —
    /// surfaced so an operator can tell "discovery off" apart from "discovery
    /// on but nothing fetched yet".
    pub discovery_enabled: bool,
    /// Remote clusters this DP has fetched endpoints from, sorted by
    /// `cluster_name` for stable byte-identical responses across polls.
    pub discovered: Vec<DiscoveredRemoteCluster>,
    /// Remote clusters declared in the accepted slice, sorted by
    /// `cluster_name`. Empty when no slice has been accepted or the accepted
    /// slice declares no `MultiClusterConfig`.
    pub configured: Vec<ConfiguredRemoteCluster>,
}

/// Inputs for the response builder. Kept as a struct so the unit tests can
/// stage state without constructing a `MeshRuntimeState` / `EnvConfig`, and so
/// the handler is one literal away from a JSON response.
pub struct MeshRemoteClustersInputs<'a> {
    /// Live remote-endpoint snapshot from
    /// [`crate::modes::mesh::multicluster::RemoteEndpointStore::snapshot`].
    pub snapshot: &'a RemoteEndpointSnapshot,
    /// The accepted slice's `MultiClusterConfig`, if any. `None` when no slice
    /// has been accepted or the slice carries no multicluster config — the
    /// `configured` list is then empty.
    pub multi_cluster: Option<&'a MultiClusterConfig>,
    /// Live federation bundle snapshot from
    /// [`crate::modes::mesh::federation::FederationStore::snapshot`].
    pub federation: &'a FederationSnapshot,
    /// Accepted slice's trust bundles, if present.
    pub trust_bundles: Option<&'a TrustBundleSet>,
    /// Whether discovery is enabled (poll interval > 0). Passed in rather than
    /// derived from the snapshot because an enabled-but-not-yet-converged
    /// discovery has an empty snapshot, indistinguishable from disabled.
    pub discovery_enabled: bool,
    /// Whether trust-bundle federation polling is enabled.
    pub federation_poll_enabled: bool,
    /// Effective `FERRUM_MESH_FEDERATION_FAIL_OPEN` value.
    pub federation_fail_open: bool,
    /// Whether inbound mesh SPIFFE peer verification has a live verifier slot.
    pub inbound_spiffe_verifier_configured: bool,
    /// Wall-clock "now" as a Unix timestamp (seconds) used to compute
    /// `age_seconds`. Injected so unit tests are deterministic.
    pub now_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteTrustStatus {
    outbound_trust_active: bool,
    inbound_trust_active: bool,
    trust_source: &'static str,
    fetched_at_unix_seconds: Option<u64>,
    age_seconds: Option<u64>,
}

fn endpoint_configured(remote: &RemoteCluster) -> bool {
    remote
        .federation_endpoint
        .as_deref()
        .is_some_and(|url| !url.trim().is_empty())
}

fn trust_bundle_set_contains_remote_domain(
    bundles: &TrustBundleSet,
    remote: &RemoteCluster,
) -> bool {
    bundles.local.trust_domain == remote.trust_domain
        || bundles
            .federated
            .iter()
            .any(|bundle| bundle.trust_domain == remote.trust_domain)
}

fn remote_trust_status(
    remote: &RemoteCluster,
    inputs: &MeshRemoteClustersInputs<'_>,
    federation_endpoint_configured: bool,
    effective_trust_bundles: Option<&TrustBundleSet>,
) -> RemoteTrustStatus {
    let effective_bundle_present = effective_trust_bundles
        .is_some_and(|bundles| trust_bundle_set_contains_remote_domain(bundles, remote));

    if let Some(bundle) = inputs.federation.bundles.get(&remote.trust_domain) {
        if !effective_bundle_present {
            return RemoteTrustStatus {
                outbound_trust_active: false,
                inbound_trust_active: false,
                trust_source: TRUST_SOURCE_NONE,
                fetched_at_unix_seconds: None,
                age_seconds: None,
            };
        }
        let fetched_at = bundle.fetched_at_unix_seconds;
        return RemoteTrustStatus {
            outbound_trust_active: true,
            inbound_trust_active: inputs.inbound_spiffe_verifier_configured,
            trust_source: TRUST_SOURCE_POLLED,
            fetched_at_unix_seconds: Some(fetched_at),
            age_seconds: Some(inputs.now_unix_seconds.saturating_sub(fetched_at)),
        };
    }

    let cp_bundle_present = inputs
        .trust_bundles
        .is_some_and(|bundles| trust_bundle_set_contains_remote_domain(bundles, remote));

    if !cp_bundle_present {
        return RemoteTrustStatus {
            outbound_trust_active: false,
            inbound_trust_active: false,
            trust_source: TRUST_SOURCE_NONE,
            fetched_at_unix_seconds: None,
            age_seconds: None,
        };
    }

    let source = if inputs
        .trust_bundles
        .is_some_and(|bundles| bundles.local.trust_domain == remote.trust_domain)
    {
        TRUST_SOURCE_LOCAL
    } else if inputs.federation_poll_enabled
        && federation_endpoint_configured
        && !inputs.federation_fail_open
    {
        TRUST_SOURCE_BLOCKED_PENDING_POLL
    } else {
        TRUST_SOURCE_CONTROL_PLANE
    };
    let active = source != TRUST_SOURCE_BLOCKED_PENDING_POLL && effective_bundle_present;

    RemoteTrustStatus {
        outbound_trust_active: active,
        inbound_trust_active: active && inputs.inbound_spiffe_verifier_configured,
        trust_source: source,
        fetched_at_unix_seconds: None,
        age_seconds: None,
    }
}

/// Build the response from staged inputs. Pure function — no I/O, no clock
/// reads. Unit-tested directly to lock down the shape.
///
/// Both views are derived from the **accepted** slice's `MultiClusterConfig`.
/// The discovery store itself is now reconciled from the *accepted* slice too
/// (`start_remote_cluster_discovery_reconcile_task` reads `applied_snapshot`),
/// so it can no longer be populated from a slice the proxy REJECTED — a
/// rejected slice that changes any poll-identity field (`network`,
/// `control_plane_url`, trust domain, …) for the same cluster name never starts
/// a poller. This accepted-scope filter is a second guard: a discovered cluster
/// is surfaced only when an accepted `RemoteCluster` matches the stored entry's
/// **full poll identity** — name, trust domain, network, AND normalized
/// `control_plane_url` — via
/// [`crate::modes::mesh::multicluster::RemoteClusterEntry::matches_declared`]. So a
/// cluster absent from the accepted config, or present under a different trust
/// domain / network / control-plane URL, is **omitted** from `discovered`, and
/// the store-side and filter-side guards must both pass. Matching the URL too
/// (codex F7.2 round-5) means even a same-name + same-trust-domain entry whose
/// network or CP URL diverges from the accepted slice (e.g. a still-running
/// poller's last-good entry during a URL change) is never reported as
/// `discovered` with its stale network. Fail closed: when no slice is accepted
/// (or it carries no `MultiClusterConfig`), `discovered` is empty regardless of
/// what the store holds.
pub fn build_response(inputs: MeshRemoteClustersInputs<'_>) -> MeshRemoteClustersResponse {
    // Accepted remote-cluster declarations. A discovery entry is surfaced only
    // when one of these matches its full poll identity (name + trust domain +
    // network + normalized control_plane_url), so a rejected slice's clusters —
    // or a stale entry whose identity diverges from the accepted slice — never
    // appear as live discovery. Empty slice when no multicluster config is
    // accepted.
    let accepted: &[RemoteCluster] = inputs
        .multi_cluster
        .map(|mc| mc.remote_clusters.as_slice())
        .unwrap_or_default();

    // Discovered view: one entry per fetched cluster, counts only — filtered to
    // the accepted slice's clusters by full poll identity. The store is
    // reconciled from the accepted slice, so this is a second guard: any cluster
    // whose identity is not declared by the accepted config is omitted
    // regardless of how it got into the store.
    let mut discovered: Vec<DiscoveredRemoteCluster> = inputs
        .snapshot
        .clusters
        .values()
        .filter(|entry| {
            accepted
                .iter()
                .any(|declared| entry.matches_declared(declared))
        })
        .map(|entry| {
            // Read the shared poll-timestamp atomic ONCE so the reported
            // `fetched_at_unix_seconds` and the derived `age_seconds` are
            // computed from the same value (a concurrent poll could refresh the
            // atomic between two reads, otherwise yielding an inconsistent pair).
            let fetched_at = entry.fetched_at_unix_seconds();
            DiscoveredRemoteCluster {
                cluster_name: entry.cluster_name.clone(),
                trust_domain: entry.trust_domain.as_str().to_string(),
                network: entry.network.clone(),
                workload_count: entry.endpoints.workloads.len(),
                service_count: entry.endpoints.services.len(),
                fetched_at_unix_seconds: fetched_at,
                // Saturating sub: a fetch timestamp ahead of `now` (clock skew on
                // the remote CP's clock vs ours) maps to `0` rather than wrapping.
                age_seconds: inputs.now_unix_seconds.saturating_sub(fetched_at),
            }
        })
        .collect();
    discovered.sort_by(|a, b| a.cluster_name.cmp(&b.cluster_name));

    // Names that survived the accepted-scope filter, so the `configured`
    // view's `discovered` flag reflects the SAME scoped set the operator sees
    // under `discovered` (never a rejected-slice cluster).
    let discovered_names: HashSet<&str> =
        discovered.iter().map(|d| d.cluster_name.as_str()).collect();

    // Configured view: one entry per declared remote cluster. `discovered`
    // flag cross-references the scoped discovered set so operators see at a
    // glance which configured clusters are actually returning endpoints.
    let effective_trust_bundles =
        crate::modes::mesh::federation::merge_federation_into_trust_bundles(
            inputs.trust_bundles.cloned(),
            inputs.federation,
            inputs.multi_cluster,
            inputs.federation_fail_open,
            inputs.federation_poll_enabled,
        );
    let configured: Vec<ConfiguredRemoteCluster> = inputs
        .multi_cluster
        .map(|mc| {
            let mut entries: Vec<ConfiguredRemoteCluster> = mc
                .remote_clusters
                .iter()
                .map(|remote| {
                    let federation_endpoint_configured = endpoint_configured(remote);
                    let trust_status = remote_trust_status(
                        remote,
                        &inputs,
                        federation_endpoint_configured,
                        effective_trust_bundles.as_ref(),
                    );
                    let control_plane_configured = remote
                        .control_plane_url
                        .as_deref()
                        .is_some_and(|url| !url.trim().is_empty());
                    ConfiguredRemoteCluster {
                        cluster_name: remote.name.clone(),
                        trust_domain: remote.trust_domain.as_str().to_string(),
                        network: remote.network.clone(),
                        control_plane_configured,
                        federation_endpoint_configured,
                        discovery_audience: control_plane_configured.then(|| {
                            crate::grpc::auth::remote_discovery_audience(&remote.name)
                        }),
                        discovered: discovered_names.contains(remote.name.as_str()),
                        outbound_trust_active: trust_status.outbound_trust_active,
                        inbound_trust_active: trust_status.inbound_trust_active,
                        trust_source: trust_status.trust_source.to_string(),
                        trust_bundle_fetched_at_unix_seconds: trust_status.fetched_at_unix_seconds,
                        trust_bundle_age_seconds: trust_status.age_seconds,
                    }
                })
                .collect();
            entries.sort_by(|a, b| a.cluster_name.cmp(&b.cluster_name));
            entries
        })
        .unwrap_or_default();

    MeshRemoteClustersResponse {
        discovery_enabled: inputs.discovery_enabled,
        discovered,
        configured,
    }
}
