//! External coverage for durable Ferrum CNI GC ownership (#3225 repair).
//!
//! Focuses on the node-local ownership store: socket-bound path identity,
//! crash-safe round-trip of cleanup snapshots, fail-closed rejection of
//! malformed / hostile durable state, TOCTOU-safe regular-file loads, and
//! encoder uniqueness for `(container_id, ifname)` without echoing
//! attacker-controlled identifiers.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use ferrum_edge::cni::ownership::{
    CNI_OWNERSHIP_STORE_FILENAME_PREFIX, CNI_OWNERSHIP_STORE_FILENAME_SUFFIX,
    CniOwnershipStoreError, CniOwnershipStoreState, DurableCniCleanupSnapshot,
    DurableCniOwnershipRecord, MAX_CNI_OWNERSHIP_STORE_BYTES, configure_cni_ownership_store,
    load_durable_cni_ownership, ownership_store_id_for_socket, ownership_store_path_for_socket,
    parse_durable_cni_ownership_bytes, reset_cni_ownership_store_for_tests,
    store_durable_cni_ownership,
};
use ferrum_edge::cni::spec::MAX_CNI_ATTACHMENT_FIELD_BYTES;

fn sample_cleanup() -> DurableCniCleanupSnapshot {
    DurableCniCleanupSnapshot {
        attached: true,
        pod_ip: Some(Ipv4Addr::new(10, 0, 0, 9)),
        pod_ip6: None,
        include_ports_cgroup_ids: vec![11],
        workload_identity_cgroup_ids: vec![22],
        node_probe_ports: vec![8080],
        inbound_redirect_ports: vec![80],
    }
}

#[test]
fn ownership_store_path_is_bound_to_exact_socket_path_identity() {
    let a = ownership_store_path_for_socket("/var/run/ferrum/node-agent-cni.sock")
        .expect("socket parent");
    let b =
        ownership_store_path_for_socket("/var/run/ferrum/other-cni.sock").expect("socket parent");
    assert_ne!(
        a, b,
        "distinct sockets in the same parent must not share a durable store file"
    );
    assert_eq!(a.parent(), b.parent());
    let id_a = ownership_store_id_for_socket("/var/run/ferrum/node-agent-cni.sock").expect("id");
    assert!(
        a.file_name().and_then(|n| n.to_str()).is_some_and(|name| {
            name.starts_with(CNI_OWNERSHIP_STORE_FILENAME_PREFIX)
                && name.ends_with(CNI_OWNERSHIP_STORE_FILENAME_SUFFIX)
                && name.contains(&id_a)
                && !name.contains("node-agent-cni.sock")
        }),
        "store filename must embed a digest identity without raw socket path bytes: {a:?}"
    );
    assert_eq!(
        a,
        PathBuf::from("/var/run/ferrum").join(format!(
            "{CNI_OWNERSHIP_STORE_FILENAME_PREFIX}{id_a}{CNI_OWNERSHIP_STORE_FILENAME_SUFFIX}"
        ))
    );
    assert!(ownership_store_path_for_socket("").is_none());
    assert!(ownership_store_path_for_socket("node-agent-cni.sock").is_none());
}

#[test]
fn durable_ownership_round_trip_persists_cleanup_snapshot() {
    reset_cni_ownership_store_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cni-owned-attachments.test.v2");
    let records = vec![
        DurableCniOwnershipRecord {
            network_name: "ferrum-mesh".into(),
            container_id: "ctr-a".into(),
            ifname: "eth0".into(),
            pod_uid: "pod-uid-1".into(),
            cleanup: sample_cleanup(),
        },
        DurableCniOwnershipRecord {
            network_name: "ferrum-mesh".into(),
            container_id: "ctr-b".into(),
            ifname: "eth1".into(),
            pod_uid: "pod-uid-2".into(),
            cleanup: DurableCniCleanupSnapshot {
                attached: true,
                pod_ip: None,
                pod_ip6: None,
                include_ports_cgroup_ids: Vec::new(),
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
                inbound_redirect_ports: Vec::new(),
            },
        },
    ];
    store_durable_cni_ownership(&path, &records).expect("store");
    let loaded = load_durable_cni_ownership(&path).expect("load");
    assert_eq!(loaded, records);
    assert!(loaded[0].cleanup.attached);
    assert_eq!(loaded[0].cleanup.pod_ip, Some(Ipv4Addr::new(10, 0, 0, 9)));
    assert_eq!(loaded[0].cleanup.include_ports_cgroup_ids, vec![11]);
    assert_eq!(loaded[0].cleanup.workload_identity_cgroup_ids, vec![22]);
    assert_eq!(loaded[0].cleanup.node_probe_ports, vec![8080]);
    assert_eq!(loaded[0].cleanup.inbound_redirect_ports, vec![80]);

    // Missing file is empty ownership, not an error.
    let missing = dir.path().join("missing.v2");
    assert!(
        load_durable_cni_ownership(&missing)
            .expect("missing")
            .is_empty()
    );

    configure_cni_ownership_store(Some(path));
    reset_cni_ownership_store_for_tests();
}

#[test]
fn inconsistent_detached_cleanup_snapshot_is_rejected_on_decode_and_encode() {
    let inconsistent = br#"{"version":2,"attachments":[{"network_name":"ferrum-mesh","container_id":"ctr-stale","ifname":"eth0","pod_uid":"pod-uid-stale","cleanup":{"attached":false,"pod_ip":"10.0.0.9","include_ports_cgroup_ids":[11]}}]}"#;
    let decode_err = parse_durable_cni_ownership_bytes(inconsistent)
        .expect_err("detached cleanup with persisted resource keys must fail closed");
    assert!(decode_err.to_string().contains("invalid"));

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("inconsistent.v2");
    let encode_err = store_durable_cni_ownership(
        &path,
        &[DurableCniOwnershipRecord {
            network_name: "ferrum-mesh".into(),
            container_id: "ctr-stale".into(),
            ifname: "eth0".into(),
            pod_uid: "pod-uid-stale".into(),
            cleanup: DurableCniCleanupSnapshot {
                attached: false,
                pod_ip: Some(Ipv4Addr::new(10, 0, 0, 9)),
                pod_ip6: None,
                include_ports_cgroup_ids: vec![11],
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
                inbound_redirect_ports: Vec::new(),
            },
        }],
    )
    .expect_err("encoder must refuse impossible detached ownership snapshots");
    assert!(encode_err.to_string().contains("invalid"));
    assert!(!path.exists(), "rejected snapshot must not become durable");
}

#[test]
fn encoder_rejects_duplicate_attachment_identity() {
    let dup = vec![
        DurableCniOwnershipRecord {
            network_name: "ferrum-mesh".into(),
            container_id: "ctr-a".into(),
            ifname: "eth0".into(),
            pod_uid: "pod-uid-1".into(),
            cleanup: sample_cleanup(),
        },
        DurableCniOwnershipRecord {
            network_name: "ferrum-mesh".into(),
            container_id: "ctr-a".into(),
            ifname: "eth0".into(),
            pod_uid: "pod-uid-2".into(),
            cleanup: sample_cleanup(),
        },
    ];
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dup.v2");
    let err = store_durable_cni_ownership(&path, &dup).expect_err("duplicate");
    assert!(
        err.to_string().contains("invalid"),
        "duplicate attachment identity must fail closed, got: {err}"
    );
    assert!(
        !path.exists(),
        "failed encode must not leave a durable file"
    );
}

#[test]
fn ownership_identity_is_network_scoped_and_shared_pod_cleanup_must_agree() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("network-scoped.v2");
    let mut second_network = DurableCniOwnershipRecord {
        network_name: "network-b".into(),
        container_id: "ctr-a".into(),
        ifname: "eth0".into(),
        pod_uid: "pod-uid-1".into(),
        cleanup: sample_cleanup(),
    };
    let records = vec![
        DurableCniOwnershipRecord {
            network_name: "network-a".into(),
            ..second_network.clone()
        },
        second_network.clone(),
    ];
    store_durable_cni_ownership(&path, &records)
        .expect("the same attachment tuple in distinct networks is not a duplicate");
    assert_eq!(
        load_durable_cni_ownership(&path)
            .expect("load network-scoped claims")
            .len(),
        2
    );

    second_network.cleanup.node_probe_ports.push(9090);
    let inconsistent = vec![records[0].clone(), second_network];
    let err = store_durable_cni_ownership(&path, &inconsistent)
        .expect_err("one pod cannot carry conflicting cleanup authority");
    assert!(err.to_string().contains("invalid"));
}

#[test]
fn malformed_oversized_and_hostile_durable_state_fail_closed_without_echo() {
    let oversized_id = "a".repeat(MAX_CNI_ATTACHMENT_FIELD_BYTES + 1);
    let oversized = format!(
        "{{\"version\":2,\"attachments\":[{{\"network_name\":\"ferrum-mesh\",\"container_id\":\"{oversized_id}\",\"ifname\":\"eth0\",\"pod_uid\":\"uid\",\"cleanup\":{{\"attached\":true}}}}]}}"
    );
    let err = parse_durable_cni_ownership_bytes(oversized.as_bytes()).expect_err("reject");
    assert!(!err.to_string().contains(&oversized_id));

    let path_like = br#"{"version":2,"attachments":[{"network_name":"ferrum-mesh","container_id":"../escape","ifname":"eth0","pod_uid":"uid","cleanup":{"attached":true}}]}"#;
    let err = parse_durable_cni_ownership_bytes(path_like).expect_err("reject");
    assert!(!err.to_string().contains("../escape"));

    let truncated = br#"{"version":2,"attachments":[{"container_id":"ctr""#;
    assert!(parse_durable_cni_ownership_bytes(truncated).is_err());

    let legacy_v1 =
        br#"{"version":1,"attachments":[{"container_id":"ctr","ifname":"eth0","pod_uid":"uid"}]}"#;
    assert!(
        parse_durable_cni_ownership_bytes(legacy_v1).is_err(),
        "replaced schema must fail closed on legacy identity-only documents"
    );

    let too_big = vec![b'x'; MAX_CNI_OWNERSHIP_STORE_BYTES + 1];
    let err = parse_durable_cni_ownership_bytes(&too_big).expect_err("size");
    assert!(err.to_string().contains("size") || err.to_string().contains("cap"));
}

#[cfg(unix)]
#[test]
fn symlinked_durable_ownership_store_is_rejected() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("target");
    std::fs::write(&target, b"{}").expect("seed");
    let path = dir.path().join("cni-owned-attachments.link.v2");
    symlink(&target, &path).expect("symlink");
    let err = load_durable_cni_ownership(&path).expect_err("symlink");
    assert!(
        err.to_string().contains("symlink") || err.to_string().contains("non-regular"),
        "expected symlink rejection, got: {err}"
    );
}

#[cfg(unix)]
#[test]
fn hard_linked_durable_ownership_store_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cni-owned-attachments.hl.v2");
    let records = vec![DurableCniOwnershipRecord {
        network_name: "ferrum-mesh".into(),
        container_id: "ctr-a".into(),
        ifname: "eth0".into(),
        pod_uid: "pod-uid-1".into(),
        cleanup: sample_cleanup(),
    }];
    store_durable_cni_ownership(&path, &records).expect("store");
    let link = dir.path().join("hardlink.v2");
    std::fs::hard_link(&path, &link).expect("hardlink");
    let write_err = store_durable_cni_ownership(&path, &records).expect_err("hardlink write");
    assert!(
        write_err.to_string().contains("hard-linked")
            || write_err.to_string().contains("non-regular"),
        "expected hard-link write rejection, got: {write_err}"
    );
    let err = load_durable_cni_ownership(&path).expect_err("hardlink");
    assert!(
        err.to_string().contains("hard-linked") || err.to_string().contains("non-regular"),
        "expected hard-link rejection, got: {err}"
    );
}

#[test]
fn oversized_existing_store_is_rejected_before_replacement() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cni-owned-attachments.oversized.v2");
    std::fs::write(&path, vec![b'x'; MAX_CNI_OWNERSHIP_STORE_BYTES + 1])
        .expect("seed oversized destination");
    let records = vec![DurableCniOwnershipRecord {
        network_name: "ferrum-mesh".into(),
        container_id: "ctr-a".into(),
        ifname: "eth0".into(),
        pod_uid: "pod-uid-1".into(),
        cleanup: sample_cleanup(),
    }];

    let err = store_durable_cni_ownership(&path, &records)
        .expect_err("oversized prior state must fail closed before publication");
    assert!(err.to_string().contains("size"));
    assert_eq!(
        std::fs::metadata(&path).expect("destination remains").len(),
        (MAX_CNI_OWNERSHIP_STORE_BYTES + 1) as u64,
        "rejected prior state must not be replaced"
    );
}

// ── Store lifecycle (explicit-state audit C3) ──────────────────────────────
//
// These drive the pure `CniOwnershipStoreState::load` transition, not the
// process-global store, so concurrently running node-agent loop tests in this
// binary (which reconfigure the global store) cannot perturb them. STATUS
// wiring against the global store is covered in `tests/integration/cni_tests.rs`.

#[test]
fn only_filesystem_io_failures_are_transient_ownership_load_errors() {
    for (error, transient) in [
        (CniOwnershipStoreError::Io, true),
        (CniOwnershipStoreError::Path, false),
        (CniOwnershipStoreError::Symlink, false),
        (CniOwnershipStoreError::NotRegular, false),
        (CniOwnershipStoreError::Oversized, false),
        (CniOwnershipStoreError::TruncatedOrInvalid, false),
        (CniOwnershipStoreError::UnsupportedVersion, false),
        (CniOwnershipStoreError::TooManyAttachments, false),
        (CniOwnershipStoreError::InvalidRecord, false),
    ] {
        assert_eq!(error.is_transient(), transient, "{error:?}");
    }
}

#[test]
fn ownership_store_refusal_covers_exactly_the_failed_load_states() {
    let path = PathBuf::from("/var/run/ferrum/cni-owned-attachments.test.v2");
    let cases = [
        (CniOwnershipStoreState::Disabled, None, false),
        (
            CniOwnershipStoreState::Configured { path: path.clone() },
            None,
            false,
        ),
        (
            CniOwnershipStoreState::Loaded { path: path.clone() },
            None,
            false,
        ),
        (
            CniOwnershipStoreState::Unavailable {
                path: path.clone(),
                error: CniOwnershipStoreError::Io,
            },
            Some("unavailable"),
            true,
        ),
        (
            CniOwnershipStoreState::Rejected {
                path,
                error: CniOwnershipStoreError::TruncatedOrInvalid,
            },
            Some("rejected"),
            false,
        ),
    ];
    for (state, refusal, retryable) in cases {
        assert_eq!(state.refusal(), refusal, "{state:?}");
        assert_eq!(state.load_is_retryable(), retryable, "{state:?}");
    }
    assert_eq!(
        CniOwnershipStoreState::Disabled.load(),
        (CniOwnershipStoreState::Disabled, Ok(None)),
    );
}

/// Before C3 any load error latched one `rejected` flag, so a transient read
/// failure was as terminal as corrupt content. A filesystem failure now leaves
/// the store `Unavailable` and a later load recovers without a restart.
#[cfg(unix)]
#[test]
fn transient_ownership_load_failure_is_retryable_until_the_store_loads() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A regular file where the parent directory should be makes the open fail
    // with ENOTDIR (an I/O error, deterministic even as root).
    let blocker = dir.path().join("not-a-directory");
    std::fs::write(&blocker, b"").expect("seed blocker file");
    let path = blocker.join("cni-owned-attachments.test.v2");

    let (state, outcome) = CniOwnershipStoreState::Configured { path: path.clone() }.load();
    assert_eq!(outcome, Err(CniOwnershipStoreError::Io));
    assert_eq!(
        state,
        CniOwnershipStoreState::Unavailable {
            path: path.clone(),
            error: CniOwnershipStoreError::Io,
        }
    );
    assert_eq!(state.refusal(), Some("unavailable"));
    assert!(state.load_is_retryable());

    let (state, outcome) = state.load();
    assert!(
        matches!(state, CniOwnershipStoreState::Unavailable { .. }),
        "an unrepaired transient failure stays retryable: {state:?}"
    );
    assert!(outcome.is_err());

    std::fs::remove_file(&blocker).expect("remove blocker");
    std::fs::create_dir(&blocker).expect("restore parent directory");
    let (state, outcome) = state.load();
    assert_eq!(outcome, Ok(Some(Vec::new())));
    assert_eq!(state, CniOwnershipStoreState::Loaded { path });
    assert_eq!(state.refusal(), None);
}

/// Invalid content is terminal for the configured generation: even a repaired
/// file is not re-read until the store is reconfigured (node-agent restart).
#[test]
fn rejected_ownership_content_is_terminal_until_reconfigured() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cni-owned-attachments.test.v2");
    std::fs::write(&path, b"{not json").expect("seed corrupt store");

    let (state, outcome) = CniOwnershipStoreState::Configured { path: path.clone() }.load();
    assert_eq!(outcome, Err(CniOwnershipStoreError::TruncatedOrInvalid));
    assert!(matches!(state, CniOwnershipStoreState::Rejected { .. }));
    assert_eq!(state.refusal(), Some("rejected"));
    assert!(!state.load_is_retryable());

    store_durable_cni_ownership(&path, &[]).expect("operator repair");
    let (still, outcome) = state.load();
    assert_eq!(still, state, "a rejected store is never re-read");
    assert_eq!(outcome, Err(CniOwnershipStoreError::TruncatedOrInvalid));

    let (reconfigured, outcome) = CniOwnershipStoreState::Configured { path: path.clone() }.load();
    assert_eq!(outcome, Ok(Some(Vec::new())));
    assert_eq!(reconfigured, CniOwnershipStoreState::Loaded { path });
}
