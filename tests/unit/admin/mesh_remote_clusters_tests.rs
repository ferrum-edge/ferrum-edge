//! Unit coverage for `GET /mesh/remote-clusters`' pure response builder
//! (`ferrum_edge::admin::mesh_remote_clusters::build_response`, F7.2).
//!
//! The builder takes a staged `RemoteEndpointSnapshot` + the accepted slice's
//! `MultiClusterConfig` and produces the JSON response shape, so the whole
//! contract — discovered/configured views, counts-only payload (no raw
//! addresses/SPIFFE/URLs), age math, sorting, and the accepted-slice scoping —
//! is exercised here without standing up a `MeshRuntimeState`, an admin
//! listener, or mutating any runtime store. The integration suite
//! (`tests/integration/admin_mesh_remote_clusters_tests.rs`) covers only what
//! genuinely needs a live gateway: JWT gating, the not-in-mesh-mode 404, and
//! the empty-discovered + configured-from-accepted-slice path.

use ferrum_edge::admin::mesh_remote_clusters::{MeshRemoteClustersInputs, build_response};
use ferrum_edge::identity::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    MeshService, MultiClusterConfig, RemoteCluster, ServicePort, TrustBundle, TrustBundleSet,
    Workload, WorkloadRef, WorkloadSelector,
};
use ferrum_edge::modes::mesh::federation::{FederatedBundle, FederationSnapshot};
use ferrum_edge::modes::mesh::multicluster::{
    RemoteClusterEndpoints, RemoteClusterEntry, RemoteEndpointSnapshot,
};
use std::collections::HashMap;

fn td(raw: &str) -> TrustDomain {
    TrustDomain::new(raw).expect("trust domain")
}

fn spiffe(raw: &str) -> SpiffeId {
    SpiffeId::new(raw.to_string()).expect("spiffe id")
}

fn workload(spiffe_id: &str, service: &str, address: &str) -> Workload {
    let id = spiffe(spiffe_id);
    let trust_domain = id.trust_domain().clone();
    Workload {
        spiffe_id: id,
        selector: WorkloadSelector::default(),
        service_name: service.to_string(),
        addresses: vec![address.to_string()],
        ports: vec![],
        trust_domain,
        namespace: "default".to_string(),
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

fn service(name: &str) -> MeshService {
    MeshService {
        cluster_ips: Vec::new(),
        name: name.to_string(),
        namespace: "default".to_string(),
        ports: vec![ServicePort {
            port: 8080,
            protocol: Default::default(),
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: vec![WorkloadRef {
            spiffe_id: spiffe("spiffe://remote.local/ns/default/sa/reviews"),
        }],
        protocol_overrides: HashMap::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn entry(
    cluster: &str,
    trust_domain: &str,
    network: Option<&str>,
    // NORMALIZED control-plane URL the entry was "polled" from. `build_response`
    // matches the FULL poll identity (name + trust domain + network + URL), so
    // tests pass the normalized form of the accepted config's `control_plane_url`
    // (e.g. `grpcs://cp:1` → `https://cp:1`) to be surfaced as `discovered`.
    control_plane_url: Option<&str>,
    workloads: Vec<Workload>,
    services: Vec<MeshService>,
    fetched_at: u64,
) -> RemoteClusterEntry {
    RemoteClusterEntry::new(
        cluster.to_string(),
        td(trust_domain),
        network.map(str::to_string),
        control_plane_url.map(str::to_string),
        RemoteClusterEndpoints {
            workloads,
            services,
        },
        fetched_at,
    )
}

fn snapshot_with(entries: Vec<RemoteClusterEntry>) -> RemoteEndpointSnapshot {
    let mut clusters = HashMap::new();
    for e in entries {
        clusters.insert(e.cluster_name.clone(), e);
    }
    RemoteEndpointSnapshot { clusters }
}

fn remote_cluster(
    name: &str,
    trust_domain: &str,
    network: Option<&str>,
    control_plane_url: Option<&str>,
    federation_endpoint: Option<&str>,
) -> RemoteCluster {
    RemoteCluster {
        name: name.to_string(),
        trust_domain: td(trust_domain),
        network: network.map(str::to_string),
        control_plane_url: control_plane_url.map(str::to_string),
        federation_endpoint: federation_endpoint.map(str::to_string),
    }
}

fn multi_cluster_with(remotes: Vec<RemoteCluster>) -> MultiClusterConfig {
    MultiClusterConfig {
        local_cluster: Some("local".to_string()),
        federation_endpoint: None,
        remote_clusters: remotes,
        east_west_gateways: Vec::new(),
    }
}

fn trust_bundles_with_federated(domains: Vec<&str>) -> TrustBundleSet {
    TrustBundleSet {
        local: TrustBundle {
            trust_domain: td("local.test"),
            x509_authorities: vec!["AQID".to_string()],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: domains
            .into_iter()
            .map(|domain| TrustBundle {
                trust_domain: td(domain),
                x509_authorities: vec!["BAUG".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            })
            .collect(),
    }
}

fn federation_snapshot_for(
    cluster: &str,
    trust_domain: &str,
    fetched_at: u64,
) -> FederationSnapshot {
    let remote_td = td(trust_domain);
    let mut snapshot = FederationSnapshot::default();
    snapshot.bundles.insert(
        remote_td.clone(),
        FederatedBundle {
            bundle: TrustBundle {
                trust_domain: remote_td,
                x509_authorities: vec!["BAUG".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            fetched_at_unix_seconds: fetched_at,
            endpoint: "https://remote.test/.well-known/spiffe".to_string(),
            cluster_name: cluster.to_string(),
        },
    );
    snapshot
}

#[test]
fn empty_when_no_discovery_and_no_config() {
    let snapshot = RemoteEndpointSnapshot::default();
    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: None,
        federation: &FederationSnapshot::default(),
        trust_bundles: None,
        discovery_enabled: false,
        federation_poll_enabled: false,
        federation_fail_open: false,
        inbound_spiffe_verifier_configured: false,
        now_unix_seconds: 1_000,
    });
    assert!(!resp.discovery_enabled);
    assert!(resp.discovered.is_empty());
    assert!(resp.configured.is_empty());
}

#[test]
fn discovered_surfaces_counts_and_age() {
    // A discovered cluster only surfaces when it is part of the ACCEPTED slice,
    // so the config must declare it (matching name + trust domain).
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        Some("net2"),
        Some("grpcs://cp.remote.local:50051"),
        None,
    )]);
    let snapshot = snapshot_with(vec![entry(
        "remote-east",
        "remote.local",
        Some("net2"),
        Some("https://cp.remote.local:50051"),
        vec![
            workload(
                "spiffe://remote.local/ns/default/sa/reviews",
                "reviews",
                "10.9.0.1",
            ),
            workload(
                "spiffe://remote.local/ns/default/sa/reviews",
                "reviews",
                "10.9.0.2",
            ),
        ],
        vec![service("reviews")],
        900,
    )]);
    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        federation: &FederationSnapshot::default(),
        trust_bundles: None,
        discovery_enabled: true,
        federation_poll_enabled: false,
        federation_fail_open: false,
        inbound_spiffe_verifier_configured: false,
        now_unix_seconds: 1_000,
    });

    assert!(resp.discovery_enabled);
    assert_eq!(resp.discovered.len(), 1);
    let d = &resp.discovered[0];
    assert_eq!(d.cluster_name, "remote-east");
    assert_eq!(d.trust_domain, "remote.local");
    assert_eq!(d.network.as_deref(), Some("net2"));
    assert_eq!(d.workload_count, 2);
    assert_eq!(d.service_count, 1);
    assert_eq!(d.fetched_at_unix_seconds, 900);
    assert_eq!(d.age_seconds, 100);
}

#[test]
fn discovered_payload_carries_no_raw_addresses_or_identities() {
    // Counts-only: the serialized discovered entry must never leak raw workload
    // addresses or SPIFFE IDs (parity with the sensitive detail kept off
    // /metrics).
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        None,
        Some("grpcs://cp.remote.local:50051"),
        None,
    )]);
    let snapshot = snapshot_with(vec![entry(
        "remote-east",
        "remote.local",
        None,
        Some("https://cp.remote.local:50051"),
        vec![workload(
            "spiffe://remote.local/ns/default/sa/reviews",
            "reviews",
            "10.9.0.1",
        )],
        vec![service("reviews")],
        900,
    )]);
    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        federation: &FederationSnapshot::default(),
        trust_bundles: None,
        discovery_enabled: true,
        federation_poll_enabled: false,
        federation_fail_open: false,
        inbound_spiffe_verifier_configured: false,
        now_unix_seconds: 1_000,
    });
    let serialized = serde_json::to_string(&resp).expect("serialize");
    assert!(
        !serialized.contains("10.9.0.1") && !serialized.contains("spiffe://"),
        "payload must not expose raw addresses or SPIFFE IDs: {serialized}"
    );
    // Control-plane URL must never appear either.
    assert!(
        !serialized.contains("grpcs://"),
        "payload must not expose control-plane URLs: {serialized}"
    );
}

#[test]
fn discovered_is_sorted_by_cluster_name() {
    let mc = multi_cluster_with(vec![
        remote_cluster("zulu", "z.local", None, Some("grpcs://z:1"), None),
        remote_cluster("alpha", "a.local", None, Some("grpcs://a:1"), None),
        remote_cluster("mike", "m.local", None, Some("grpcs://m:1"), None),
    ]);
    let snapshot = snapshot_with(vec![
        entry(
            "zulu",
            "z.local",
            None,
            Some("https://z:1"),
            vec![],
            vec![],
            10,
        ),
        entry(
            "alpha",
            "a.local",
            None,
            Some("https://a:1"),
            vec![],
            vec![],
            10,
        ),
        entry(
            "mike",
            "m.local",
            None,
            Some("https://m:1"),
            vec![],
            vec![],
            10,
        ),
    ]);
    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        federation: &FederationSnapshot::default(),
        trust_bundles: None,
        discovery_enabled: true,
        federation_poll_enabled: false,
        federation_fail_open: false,
        inbound_spiffe_verifier_configured: false,
        now_unix_seconds: 10,
    });
    let names: Vec<&str> = resp
        .discovered
        .iter()
        .map(|d| d.cluster_name.as_str())
        .collect();
    assert_eq!(names, vec!["alpha", "mike", "zulu"]);
}

#[test]
fn future_fetch_timestamp_clamps_age_to_zero() {
    // Clock skew: the remote CP stamped a fetch time ahead of our `now`.
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        None,
        Some("grpcs://cp:1"),
        None,
    )]);
    let snapshot = snapshot_with(vec![entry(
        "remote-east",
        "remote.local",
        None,
        Some("https://cp:1"),
        vec![],
        vec![],
        2_000,
    )]);
    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        federation: &FederationSnapshot::default(),
        trust_bundles: None,
        discovery_enabled: true,
        federation_poll_enabled: false,
        federation_fail_open: false,
        inbound_spiffe_verifier_configured: false,
        now_unix_seconds: 1_000,
    });
    assert_eq!(resp.discovered[0].age_seconds, 0);
}

#[test]
fn configured_reflects_declared_remotes_with_url_booleans() {
    let mc = multi_cluster_with(vec![
        remote_cluster(
            "remote-east",
            "remote.local",
            Some("net2"),
            Some("grpcs://cp.remote.local:50051"),
            Some("https://spire.remote.local/bundle"),
        ),
        // Federation-only cluster: no control plane, never discoverable.
        remote_cluster(
            "remote-west",
            "west.local",
            None,
            None,
            Some("https://spire.west.local/bundle"),
        ),
    ]);
    // Only remote-east has been discovered.
    let snapshot = snapshot_with(vec![entry(
        "remote-east",
        "remote.local",
        Some("net2"),
        Some("https://cp.remote.local:50051"),
        vec![workload(
            "spiffe://remote.local/ns/default/sa/reviews",
            "reviews",
            "10.9.0.1",
        )],
        vec![],
        900,
    )]);

    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        federation: &FederationSnapshot::default(),
        trust_bundles: None,
        discovery_enabled: true,
        federation_poll_enabled: false,
        federation_fail_open: false,
        inbound_spiffe_verifier_configured: false,
        now_unix_seconds: 1_000,
    });

    assert_eq!(resp.configured.len(), 2);
    // Sorted: remote-east before remote-west.
    let east = &resp.configured[0];
    assert_eq!(east.cluster_name, "remote-east");
    assert_eq!(east.trust_domain, "remote.local");
    assert_eq!(east.network.as_deref(), Some("net2"));
    assert!(east.control_plane_configured);
    assert!(east.federation_endpoint_configured);
    assert!(east.discovered, "remote-east is in the snapshot");

    let west = &resp.configured[1];
    assert_eq!(west.cluster_name, "remote-west");
    assert!(!west.control_plane_configured);
    assert!(west.federation_endpoint_configured);
    assert!(
        !west.discovered,
        "remote-west is configured (federation-only) but not discovered"
    );
}

#[test]
fn configured_treats_blank_urls_as_unset() {
    // Whitespace-only URLs are not real configuration — the poller's
    // `poll_targets_for_multi_cluster` trims-and-drops them, so the
    // introspection view must agree (`control_plane_configured: false`).
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-blank",
        "blank.local",
        None,
        Some("   "),
        Some(""),
    )]);
    let snapshot = RemoteEndpointSnapshot::default();
    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        federation: &FederationSnapshot::default(),
        trust_bundles: None,
        discovery_enabled: true,
        federation_poll_enabled: false,
        federation_fail_open: false,
        inbound_spiffe_verifier_configured: false,
        now_unix_seconds: 0,
    });
    assert_eq!(resp.configured.len(), 1);
    assert!(!resp.configured[0].control_plane_configured);
    assert!(!resp.configured[0].federation_endpoint_configured);
    assert!(!resp.configured[0].discovered);
}

#[test]
fn response_round_trips_and_omits_absent_network() {
    // The serialized shape must be stable for dashboards: `network` is elided
    // when absent (skip_serializing_if), counts are always present.
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        None,
        Some("grpcs://cp:1"),
        None,
    )]);
    let snapshot = snapshot_with(vec![entry(
        "remote-east",
        "remote.local",
        None,
        Some("https://cp:1"),
        vec![],
        vec![],
        500,
    )]);
    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        federation: &FederationSnapshot::default(),
        trust_bundles: None,
        discovery_enabled: true,
        federation_poll_enabled: false,
        federation_fail_open: false,
        inbound_spiffe_verifier_configured: false,
        now_unix_seconds: 500,
    });
    let value = serde_json::to_value(&resp).expect("serialize");
    assert_eq!(value["discovery_enabled"], true);
    assert!(value["discovered"][0].get("network").is_none());
    assert_eq!(value["discovered"][0]["workload_count"], 0);
    assert_eq!(value["discovered"][0]["service_count"], 0);
    assert_eq!(value["discovered"][0]["age_seconds"], 0);
    // `configured` is always an array (possibly empty), never null.
    assert!(value["configured"].is_array());
}

// ── Finding 3: discovered clusters are scoped to the ACCEPTED slice ──────────

#[test]
fn discovered_is_scoped_to_accepted_slice_clusters() {
    // The discovery store holds two clusters, but the ACCEPTED slice declares
    // only `remote-east`. `remote-rejected` is not in the accepted config and
    // MUST NOT appear as live discovery. (The store is now reconciled from the
    // accepted slice, so such an entry should not arise in production; this
    // belt-and-suspenders filter keeps it out even if it somehow does.)
    let snapshot = snapshot_with(vec![
        entry(
            "remote-east",
            "remote.local",
            Some("net2"),
            Some("https://cp.remote.local:50051"),
            vec![workload(
                "spiffe://remote.local/ns/default/sa/reviews",
                "reviews",
                "10.9.0.1",
            )],
            vec![],
            900,
        ),
        entry(
            "remote-rejected",
            "rejected.local",
            None,
            // Absent from the accepted config entirely; URL is irrelevant.
            None,
            vec![workload(
                "spiffe://rejected.local/ns/default/sa/evil",
                "evil",
                "10.6.6.6",
            )],
            vec![],
            900,
        ),
    ]);
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        Some("net2"),
        Some("grpcs://cp.remote.local:50051"),
        None,
    )]);

    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        federation: &FederationSnapshot::default(),
        trust_bundles: None,
        discovery_enabled: true,
        federation_poll_enabled: false,
        federation_fail_open: false,
        inbound_spiffe_verifier_configured: false,
        now_unix_seconds: 1_000,
    });

    let names: Vec<&str> = resp
        .discovered
        .iter()
        .map(|d| d.cluster_name.as_str())
        .collect();
    assert_eq!(
        names,
        vec!["remote-east"],
        "a discovered cluster absent from the accepted slice must be omitted"
    );
    // The configured view (one entry, remote-east) reports discovered: true.
    assert_eq!(resp.configured.len(), 1);
    assert!(resp.configured[0].discovered);
}

#[test]
fn discovered_scoping_matches_trust_domain_not_just_name() {
    // A rejected slice could reuse an accepted cluster NAME under a different
    // (attacker-chosen) trust domain. The accepted config pins `remote-east`
    // to `remote.local`; a discovered entry of the same name under
    // `evil.local` must be omitted — fail closed on the (name, trust domain)
    // pair, not the name alone.
    let snapshot = snapshot_with(vec![entry(
        "remote-east",
        "evil.local",
        None,
        // Same URL the accepted config declares: prove the trust-domain
        // mismatch alone causes omission, not a URL divergence.
        Some("https://cp.remote.local:50051"),
        vec![workload(
            "spiffe://evil.local/ns/default/sa/evil",
            "evil",
            "10.6.6.6",
        )],
        vec![],
        900,
    )]);
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        None,
        Some("grpcs://cp.remote.local:50051"),
        None,
    )]);

    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        federation: &FederationSnapshot::default(),
        trust_bundles: None,
        discovery_enabled: true,
        federation_poll_enabled: false,
        federation_fail_open: false,
        inbound_spiffe_verifier_configured: false,
        now_unix_seconds: 1_000,
    });

    assert!(
        resp.discovered.is_empty(),
        "a discovered cluster whose trust domain differs from the accepted config must be omitted"
    );
    // remote-east IS configured, but its discovered flag is false because the
    // store's same-name entry is under a different (rejected) trust domain.
    assert_eq!(resp.configured.len(), 1);
    assert!(
        !resp.configured[0].discovered,
        "the discovered flag must follow the same (name, trust domain) scoping"
    );
}

#[test]
fn discovered_filter_omits_entry_with_diverged_network() {
    // Codex F7.2 round-5: the admin-side filter now matches the FULL poll
    // identity (name + trust domain + network + normalized control_plane_url),
    // not just (name, trust domain). A store entry that keeps the accepted name
    // + trust domain but diverges on `network` (e.g. a still-running poller's
    // last-good entry while a slice changed the network for the same name) is
    // OMITTED — it is never reported as `discovered` with its stale network.
    // (The reconcile-from-accepted store fix means such an entry should not
    // arise in production; this filter is the belt-and-suspenders second guard
    // that also catches it if it somehow does.)
    let snapshot = snapshot_with(vec![entry(
        "remote-east",
        "remote.local",
        // Diverged network: the accepted config below declares `net-accepted`.
        Some("net-rejected"),
        Some("https://cp.remote.local:50051"),
        vec![workload(
            "spiffe://remote.local/ns/default/sa/reviews",
            "reviews",
            "10.9.0.1",
        )],
        vec![],
        900,
    )]);
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        Some("net-accepted"),
        Some("grpcs://cp.remote.local:50051"),
        None,
    )]);

    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        federation: &FederationSnapshot::default(),
        trust_bundles: None,
        discovery_enabled: true,
        federation_poll_enabled: false,
        federation_fail_open: false,
        inbound_spiffe_verifier_configured: false,
        now_unix_seconds: 1_000,
    });

    assert!(
        resp.discovered.is_empty(),
        "an entry whose network diverges from the accepted slice must be omitted, \
         not surfaced with its stale network"
    );
    // remote-east IS configured, but discovered is false: the only same-name
    // store entry has a diverged network.
    assert_eq!(resp.configured.len(), 1);
    assert!(
        !resp.configured[0].discovered,
        "the discovered flag follows the same full-poll-identity scoping"
    );
}

#[test]
fn discovered_filter_omits_entry_with_url_only_divergence() {
    // Codex F7.2 round-5: a URL-only change (same name + trust domain + network)
    // is the case the entry now stores `control_plane_url` to catch. The accepted
    // config moved the control plane to v2; the store still holds the v1 entry
    // (fetched from the OLD CP) until the reconciler restarts the poller. Because
    // the admin filter matches the normalized URL, the stale v1 entry is OMITTED
    // rather than reported as `discovered` against the v2 declaration.
    let snapshot = snapshot_with(vec![entry(
        "remote-east",
        "remote.local",
        Some("net2"),
        // v1 URL (normalized form); the accepted config declares v2 below.
        Some("https://cp-v1.remote.local:50051"),
        vec![workload(
            "spiffe://remote.local/ns/default/sa/reviews",
            "reviews",
            "10.9.0.1",
        )],
        vec![],
        900,
    )]);
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        Some("net2"),
        // v2 control plane (grpcs → https on normalize).
        Some("grpcs://cp-v2.remote.local:50051"),
        None,
    )]);

    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        federation: &FederationSnapshot::default(),
        trust_bundles: None,
        discovery_enabled: true,
        federation_poll_enabled: false,
        federation_fail_open: false,
        inbound_spiffe_verifier_configured: false,
        now_unix_seconds: 1_000,
    });

    assert!(
        resp.discovered.is_empty(),
        "a stale entry from the previous control plane must not be reported as \
         discovered against the newly-declared control_plane_url"
    );
    assert_eq!(resp.configured.len(), 1);
    assert!(!resp.configured[0].discovered);
}

#[test]
fn discovered_filter_matches_grpcs_declaration_against_normalized_entry() {
    // The accepted config carries the operator-written `grpcs://` scheme; the
    // stored entry carries the NORMALIZED `https://` poll URL. The filter
    // normalizes the declaration before comparing, so they match and the cluster
    // is surfaced as discovered. (Guards against a regression where the filter
    // compared the raw operator scheme against the normalized stored scheme.)
    let snapshot = snapshot_with(vec![entry(
        "remote-east",
        "remote.local",
        Some("net2"),
        Some("https://cp.remote.local:50051"),
        vec![workload(
            "spiffe://remote.local/ns/default/sa/reviews",
            "reviews",
            "10.9.0.1",
        )],
        vec![],
        900,
    )]);
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        Some("net2"),
        Some("grpcs://cp.remote.local:50051"),
        None,
    )]);

    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        federation: &FederationSnapshot::default(),
        trust_bundles: None,
        discovery_enabled: true,
        federation_poll_enabled: false,
        federation_fail_open: false,
        inbound_spiffe_verifier_configured: false,
        now_unix_seconds: 1_000,
    });

    assert_eq!(resp.discovered.len(), 1);
    assert_eq!(resp.discovered[0].cluster_name, "remote-east");
    assert!(resp.configured[0].discovered);
}

#[test]
fn no_accepted_slice_means_no_discovered_clusters() {
    // Fail closed: with no accepted MultiClusterConfig, nothing the store holds
    // is the DP's effective discovery — `discovered` is empty even when the
    // store is populated (e.g. from a slice that was received but rejected).
    let snapshot = snapshot_with(vec![entry(
        "remote-east",
        "remote.local",
        None,
        // No accepted slice at all; URL is irrelevant to this fail-closed case.
        None,
        vec![workload(
            "spiffe://remote.local/ns/default/sa/reviews",
            "reviews",
            "10.9.0.1",
        )],
        vec![],
        900,
    )]);
    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: None,
        federation: &FederationSnapshot::default(),
        trust_bundles: None,
        discovery_enabled: true,
        federation_poll_enabled: false,
        federation_fail_open: false,
        inbound_spiffe_verifier_configured: false,
        now_unix_seconds: 1_000,
    });
    assert!(
        resp.discovered.is_empty(),
        "no accepted multicluster config → no discovered clusters"
    );
    assert!(resp.configured.is_empty());
}

#[test]
fn configured_trust_fail_closed_blocks_control_plane_fallback_before_poll() {
    let snapshot = RemoteEndpointSnapshot::default();
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        None,
        None,
        Some("https://remote.test/.well-known/spiffe"),
    )]);
    let trust_bundles = trust_bundles_with_federated(vec!["remote.local"]);
    let federation = FederationSnapshot::default();

    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        federation: &federation,
        trust_bundles: Some(&trust_bundles),
        discovery_enabled: false,
        federation_poll_enabled: true,
        federation_fail_open: false,
        inbound_spiffe_verifier_configured: true,
        now_unix_seconds: 1_000,
    });

    let configured = &resp.configured[0];
    assert!(!configured.outbound_trust_active);
    assert!(!configured.inbound_trust_active);
    assert_eq!(configured.trust_source, "blocked_pending_poll");
}

#[test]
fn configured_trust_fail_open_uses_control_plane_fallback_before_poll() {
    let snapshot = RemoteEndpointSnapshot::default();
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        None,
        None,
        Some("https://remote.test/.well-known/spiffe"),
    )]);
    let trust_bundles = trust_bundles_with_federated(vec!["remote.local"]);
    let federation = FederationSnapshot::default();

    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        federation: &federation,
        trust_bundles: Some(&trust_bundles),
        discovery_enabled: false,
        federation_poll_enabled: true,
        federation_fail_open: true,
        inbound_spiffe_verifier_configured: true,
        now_unix_seconds: 1_000,
    });

    let configured = &resp.configured[0];
    assert!(configured.outbound_trust_active);
    assert!(configured.inbound_trust_active);
    assert_eq!(configured.trust_source, "control_plane");
}

#[test]
fn configured_trust_reports_polled_bundle_freshness() {
    let snapshot = RemoteEndpointSnapshot::default();
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        None,
        None,
        Some("https://remote.test/.well-known/spiffe"),
    )]);
    let trust_bundles = trust_bundles_with_federated(vec![]);
    let federation = federation_snapshot_for("remote-east", "remote.local", 900);

    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        federation: &federation,
        trust_bundles: Some(&trust_bundles),
        discovery_enabled: false,
        federation_poll_enabled: true,
        federation_fail_open: false,
        inbound_spiffe_verifier_configured: true,
        now_unix_seconds: 1_000,
    });

    let configured = &resp.configured[0];
    assert!(configured.outbound_trust_active);
    assert!(configured.inbound_trust_active);
    assert_eq!(configured.trust_source, "polled");
    assert_eq!(configured.trust_bundle_fetched_at_unix_seconds, Some(900));
    assert_eq!(configured.trust_bundle_age_seconds, Some(100));
}

#[test]
fn configured_trust_does_not_report_unpublished_polled_bundle_active() {
    let snapshot = RemoteEndpointSnapshot::default();
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        None,
        None,
        Some("https://remote.test/.well-known/spiffe"),
    )]);
    let federation = federation_snapshot_for("remote-east", "remote.local", 900);

    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        federation: &federation,
        trust_bundles: None,
        discovery_enabled: false,
        federation_poll_enabled: true,
        federation_fail_open: false,
        inbound_spiffe_verifier_configured: true,
        now_unix_seconds: 1_000,
    });

    let configured = &resp.configured[0];
    assert!(!configured.outbound_trust_active);
    assert!(!configured.inbound_trust_active);
    assert_eq!(configured.trust_source, "none");
    assert_eq!(configured.trust_bundle_fetched_at_unix_seconds, None);
    assert_eq!(configured.trust_bundle_age_seconds, None);
}

#[test]
fn configured_trust_exposes_outbound_inbound_asymmetry() {
    let snapshot = RemoteEndpointSnapshot::default();
    let mc = multi_cluster_with(vec![remote_cluster(
        "remote-east",
        "remote.local",
        None,
        None,
        Some("https://remote.test/.well-known/spiffe"),
    )]);
    let trust_bundles = trust_bundles_with_federated(vec!["remote.local"]);
    let federation = FederationSnapshot::default();

    let resp = build_response(MeshRemoteClustersInputs {
        snapshot: &snapshot,
        multi_cluster: Some(&mc),
        federation: &federation,
        trust_bundles: Some(&trust_bundles),
        discovery_enabled: false,
        federation_poll_enabled: true,
        federation_fail_open: true,
        inbound_spiffe_verifier_configured: false,
        now_unix_seconds: 1_000,
    });

    let configured = &resp.configured[0];
    assert!(configured.outbound_trust_active);
    assert!(!configured.inbound_trust_active);
    assert_eq!(configured.trust_source, "control_plane");
}
