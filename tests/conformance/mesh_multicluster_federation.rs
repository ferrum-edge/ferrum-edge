//! Multicluster federation GA-contract semantics (issue #2459).
//!
//! Pins the *config-plane* half of the live-proven two-cluster east-west
//! federation surface hermetically (no kind, no SPIRE):
//!
//! 1. A remote cluster whose trust domain is neither local nor federated
//!    fails slice validation (fail-closed trust boundary).
//! 2. Federated trust domains must be unique and non-empty.
//! 3. `local_cluster` identity rejects blank / whitespace-aliased names.
//! 4. Remote cluster names are unique by the same canonical identity the
//!    discovery audience uses.
//! 5. Peer-trust withdrawal (dropping the matching federated bundle while a
//!    remote remains declared) fails validation again — the semantic twin of
//!    the live suite's revoke → fail-closed path.
//!
//! The *runtime* half is live-gated by the `multicluster.*` assertions in
//! `tests/k8s/multicluster-federation/run.sh`, whose own
//! `ferrum_live_assertions_require_all_passed` call fails the live job on any
//! required assertion that is missing, failed, or skipped. The workflow's
//! `gate` job then re-validates the artifact the run actually published
//! (`.github/scripts/validate_live_assertions.py`: exact schema, suite,
//! commit, and platform profile, freshness, no duplicates, exactly the
//! required id set, every required id `pass`) — the live job itself carries no
//! validator because the trusted Cross build policy freezes its per-job
//! digest. The binding between those required id sets and the enforced
//! `multicluster-federation` rows of `ga_contract.yaml` is pinned by
//! `live_contract::live_contract_real_contract_declares_the_multicluster_suite_rows`,
//! `live_contract::live_contract_multicluster_fixture_requires_exactly_the_enforced_rows`,
//! and
//! `live_contract::live_contract_multicluster_release_gate_requires_exactly_the_enforced_rows`
//! in this hosted conformance suite. Cross-cluster
//! endpoint *discovery* (poller-driven) remains Experimental and is excluded
//! from these rows.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MultiClusterConfig, RemoteCluster, TrustBundle, TrustBundleSet,
};

use crate::conformance::registry::{Maturity, Status};

const CATEGORY: &str = "mesh_multicluster_federation";

fn td(raw: &str) -> TrustDomain {
    TrustDomain::new(raw).expect("trust domain")
}

fn authority(label: &[u8]) -> String {
    B64.encode(label)
}

fn local_and_federated_bundles(local: &str, federated: &str) -> TrustBundleSet {
    TrustBundleSet {
        local: TrustBundle {
            trust_domain: td(local),
            x509_authorities: vec![authority(b"local-root")],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: vec![TrustBundle {
            trust_domain: td(federated),
            x509_authorities: vec![authority(b"federated-root")],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        }],
    }
}

fn remote(name: &str, trust_domain: &str) -> RemoteCluster {
    RemoteCluster {
        name: name.to_string(),
        trust_domain: td(trust_domain),
        network: Some("net-b".to_string()),
        control_plane_url: None,
        federation_endpoint: None,
        discovery_credential_ref: None,
    }
}

/// A declared remote cluster whose trust domain is missing from the federated
/// trust set must fail closed at validation — otherwise the live suite's
/// SPIRE-federated inbound verifier could be configured with no matching
/// authority and the gate would be vacuous.
#[test]
fn remote_cluster_requires_federated_trust_bundle() {
    register_feature!(
        category = CATEGORY,
        feature = "remote cluster requires federated trust bundle",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "MultiClusterConfig remotes whose trust domain is neither local nor \
                 federated fail MeshConfig::validate. Live-gated via \
                 multicluster.federation.trust_bundle_exchange / \
                 multicluster.spire.federation_ready_* in multicluster-federation.",
    );

    let mut mesh = MeshConfig {
        trust_bundles: Some(TrustBundleSet {
            local: TrustBundle {
                trust_domain: td("cluster-a.test"),
                x509_authorities: vec![authority(b"local-root")],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: Vec::new(),
        }),
        multi_cluster: Some(MultiClusterConfig {
            local_cluster: Some("cluster-a".to_string()),
            remote_clusters: vec![remote("cluster-b", "cluster-b.test")],
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };

    let errors = mesh.validate();
    assert!(
        errors
            .iter()
            .any(|err| err.contains("no matching federated trust bundle")),
        "expected federated-bundle requirement, got: {errors:?}"
    );

    mesh.trust_bundles = Some(local_and_federated_bundles(
        "cluster-a.test",
        "cluster-b.test",
    ));
    assert!(
        mesh.validate().is_empty(),
        "matching federated bundle must admit the remote: {:?}",
        mesh.validate()
    );
}

/// Federated trust domains must be unique and carry authorities — a duplicate
/// or empty federated entry is rejected rather than silently dropping one peer.
#[test]
fn federated_trust_domain_uniqueness() {
    register_feature!(
        category = CATEGORY,
        feature = "federated trust domain uniqueness",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "TrustBundleSet.federated rejects duplicate trust domains and empty \
                 authorities. Live-gated via multicluster.spire.workload_entries and \
                 the bidirectional authenticated traffic assertions.",
    );

    let mesh = MeshConfig {
        trust_bundles: Some(TrustBundleSet {
            local: TrustBundle {
                trust_domain: td("cluster-a.test"),
                x509_authorities: vec![authority(b"local-root")],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: vec![
                TrustBundle {
                    trust_domain: td("cluster-b.test"),
                    x509_authorities: vec![authority(b"federated-root")],
                    jwt_authorities: Vec::new(),
                    refresh_hint_seconds: None,
                },
                TrustBundle {
                    trust_domain: td("cluster-b.test"),
                    x509_authorities: vec![authority(b"other-root")],
                    jwt_authorities: Vec::new(),
                    refresh_hint_seconds: None,
                },
            ],
        }),
        ..MeshConfig::default()
    };
    let errors = mesh.validate();
    assert!(
        errors
            .iter()
            .any(|err| err.contains("duplicate trust domain")),
        "duplicate federated trust domain must be rejected, got: {errors:?}"
    );
}

/// `local_cluster` is the operator-visible identity compared against workload
/// `cluster` labels; blank or whitespace-aliased values must fail closed.
#[test]
fn local_cluster_identity_rejects_blank_and_whitespace() {
    register_feature!(
        category = CATEGORY,
        feature = "local_cluster identity reject blank/whitespace",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "MultiClusterConfig.local_cluster rejects empty and whitespace-aliased \
                 names so remote classification cannot drift. Live-gated via \
                 multicluster.eastwest.* authenticated traffic assertions.",
    );

    for bad in ["", "   ", " cluster-a ", "\tcluster-a"] {
        let mesh = MeshConfig {
            multi_cluster: Some(MultiClusterConfig {
                local_cluster: Some(bad.to_string()),
                ..MultiClusterConfig::default()
            }),
            ..MeshConfig::default()
        };
        let errors = mesh.validate();
        assert!(!errors.is_empty(), "local_cluster {bad:?} must be rejected");
    }

    let ok = MeshConfig {
        multi_cluster: Some(MultiClusterConfig {
            local_cluster: Some("cluster-a".to_string()),
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };
    assert!(
        ok.validate().is_empty(),
        "canonical local_cluster must be accepted: {:?}",
        ok.validate()
    );
}

/// Remote cluster names key discovery audience and operator-visible config;
/// canonical-name duplicates (including whitespace aliases) fail closed.
#[test]
fn remote_cluster_names_unique_by_canonical_identity() {
    register_feature!(
        category = CATEGORY,
        feature = "remote_clusters uniqueness by canonical name",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "RemoteCluster.name uniqueness uses the same trimmed identity as the \
                 discovery audience. Live-gated via multicluster.eastwest.endpoint_* \
                 recovery assertions (distinct peer identity is a precondition).",
    );

    let mesh = MeshConfig {
        trust_bundles: Some(local_and_federated_bundles(
            "cluster-a.test",
            "cluster-b.test",
        )),
        multi_cluster: Some(MultiClusterConfig {
            remote_clusters: vec![
                remote("cluster-b", "cluster-b.test"),
                remote(" cluster-b ", "cluster-b.test"),
            ],
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };
    let errors = mesh.validate();
    assert!(
        errors.iter().any(|err| {
            err.contains("duplicate name") || err.contains("leading/trailing whitespace")
        }),
        "duplicate/aliased remote names must be rejected, got: {errors:?}"
    );
}

/// Dropping the federated bundle while the remote remains declared must fail
/// validation again — the config-plane twin of the live revoke → fail-closed
/// → restore path.
#[test]
fn federated_bundle_withdrawal_fails_closed_while_remote_declared() {
    register_feature!(
        category = CATEGORY,
        feature = "federated bundle withdrawal fails closed while remotes declared",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "Removing the matching federated trust bundle while a RemoteCluster \
                 remains declared re-fails MeshConfig::validate. Live-gated via \
                 multicluster.federation.bundle_revoked_rejected / \
                 multicluster.federation.trust_restored_recovers.",
    );

    let mut mesh = MeshConfig {
        trust_bundles: Some(local_and_federated_bundles(
            "cluster-a.test",
            "cluster-b.test",
        )),
        multi_cluster: Some(MultiClusterConfig {
            local_cluster: Some("cluster-a".to_string()),
            remote_clusters: vec![remote("cluster-b", "cluster-b.test")],
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };
    assert!(mesh.validate().is_empty());

    mesh.trust_bundles
        .as_mut()
        .expect("trust bundles")
        .federated
        .clear();
    let errors = mesh.validate();
    assert!(
        errors
            .iter()
            .any(|err| err.contains("no matching federated trust bundle")),
        "withdrawn federated bundle must fail closed, got: {errors:?}"
    );

    mesh.trust_bundles = Some(local_and_federated_bundles(
        "cluster-a.test",
        "cluster-b.test",
    ));
    assert!(
        mesh.validate().is_empty(),
        "restored federated bundle must recover: {:?}",
        mesh.validate()
    );
}

/// East-west gateway entries that front the cross-cluster hop must declare a
/// reachable host and a non-zero port; blank/zero values fail closed so a
/// blackholed destination cannot be masked by a misconfigured gateway.
#[test]
fn east_west_gateway_requires_host_and_nonzero_port() {
    register_feature!(
        category = CATEGORY,
        feature = "east-west gateway requires host and non-zero port",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "EastWestGateway.host must be non-empty and port must be non-zero. \
                 Live-gated via multicluster.eastwest.endpoint_blackhole_when_dest_down / \
                 multicluster.eastwest.endpoint_recovers_when_dest_returns.",
    );

    use ferrum_edge::modes::mesh::config::EastWestGateway;

    let mesh = MeshConfig {
        multi_cluster: Some(MultiClusterConfig {
            east_west_gateways: vec![EastWestGateway {
                name: "ew".to_string(),
                namespace: "ferrum".to_string(),
                host: String::new(),
                port: 0,
                sni_hosts: vec!["svc.ferrum.svc.cluster.local".to_string()],
                trust_domain: None,
                network: None,
            }],
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };
    let errors = mesh.validate();
    assert!(
        errors
            .iter()
            .any(|err| err.contains("host must not be empty"))
            && errors.iter().any(|err| err.contains("port")),
        "blank host / zero port must be rejected, got: {errors:?}"
    );
}
