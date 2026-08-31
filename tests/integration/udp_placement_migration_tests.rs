use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use ferrum_edge::proxy::netns_capture::{
    DirectoryCaptureSource, PodCaptureSource, PodCaptureSourceIps, PodCaptureTarget,
};
use ferrum_edge::proxy::netns_udp_capture::{NetnsUdpCleanupBackend, NetnsUdpCleanupManager};
use ferrum_edge::proxy::owned_shell::{self, OwnedShellError};
use ferrum_edge::proxy::udp_placement_cleanup::{
    HostUdpCleanupReaper, UdpCleanupOutcome, run_udp_placement_cleanup_with_host_reaper,
};
use ferrum_edge::proxy::udp_placement_migration::{
    UdpAdoptionProof, UdpCleanupProofWindow, UdpMigrationFailureReason, UdpMigrationPhase,
    UdpNodeIdentity, UdpPlacement, UdpPlacementDecision, UdpPlacementRequest, UdpRegistrySyncProof,
    clear_registry_sync_marker, node_cleanup_proof_is_current, prepare_placement,
    publish_node_identity_for, publish_registry_sync_marker_for_pods,
    resolve_authoritative_node_identity_reading_boot_id,
    resolve_authoritative_node_identity_with_boot_id, retract_node_cleanup_proof,
    retract_node_identity, validate_node_proof_generation,
    withhold_node_cleanup_proof_after_deadline,
};

/// Node identity is supplied EXPLICITLY in these tests rather than resolved
/// from the process environment, so every proof assertion is deterministic and
/// no test can race another over a shared env var or `/proc` read.
const NODE_A: &str = "11111111-1111-4111-8111-111111111111";
const NODE_B: &str = "22222222-2222-4222-8222-222222222222";
const BOOT_1: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const BOOT_2: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
/// The ERA-QUALIFIED node-proof generation a settled release carries. The
/// `e<era>` ordinal is stamped by the placement contract when a migration starts
/// and carried forward unchanged afterwards, so a token can never recur when a
/// target and phase do (issue #3809). A `<target>-<phase>`-shaped token is
/// refused outright — see
/// `a_recurring_node_proof_generation_can_never_bind_a_proof`.
const PROOF_GENERATION: &str = "e3.pod-to-host";

fn identity(node_uid: &str, boot_id: &str) -> UdpNodeIdentity {
    UdpNodeIdentity::new(node_uid, boot_id).expect("valid node identity")
}

/// Write the node-scoped attestation the privileged preflight publishes. The
/// preflight itself needs a live pod-netns/iptables environment, so these
/// deterministic tests exercise the RUNTIME BOUNDARY that consumes the artifact
/// with the exact on-disk shape the preflight writes.
fn write_node_attestation(
    registry: &std::path::Path,
    file: &str,
    node: &UdpNodeIdentity,
    target: UdpPlacement,
    generation: &str,
) {
    let document = serde_json::json!({
        "version": 1,
        "node": {"node_uid": node.node_uid, "boot_id": node.boot_id},
        "target": target.as_str(),
        "generation": generation,
    });
    std::fs::write(
        registry.join(file),
        serde_json::to_vec(&document).expect("encode attestation"),
    )
    .expect("write attestation");
}

fn age_crash_temp(path: &std::path::Path) {
    let old = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(2 * 60 * 60))
        .expect("old timestamp");
    std::fs::File::options()
        .write(true)
        .open(path)
        .expect("open crash temp")
        .set_times(std::fs::FileTimes::new().set_modified(old))
        .expect("age crash temp");
}

/// Closed inventory of chains the dual-stack node-preflight retirement scripts
/// may flush (`-F`) or delete (`-X`). Exact names only: a prefix/wildcard would
/// let a co-resident chain be swept, and a missing fail-closed guard would
/// leave predecessor DROP jumps in place.
fn is_ferrum_owned_udp_teardown_chain(chain: &str) -> bool {
    matches!(
        chain,
        "FERRUM_MESH_UDP_OUTBOUND"
            | "FERRUM_MESH_UDP_INBOUND"
            | "FERRUM_MESH_UDP_OUTPUT_MARK"
            | "FERRUM_MESH_UDP_REINJECT"
            | "FERRUM_MESH_UDP_HOST"
            | "FERRUM_MESH_UDP_HOST_GUARD_A"
            | "FERRUM_MESH_UDP_HOST_GUARD_B"
            | "FERRUM_UDP_FAIL_CLOSED_A"
            | "FERRUM_UDP_FAIL_CLOSED_B"
    )
}

/// The chain argument of a whitespace-delimited `-F` / `-X`, if that flag is
/// present. A missing operand (table-wide flush) is the empty string, which
/// the closed inventory rejects.
fn chain_named_by_flush_or_delete<'a>(line: &'a str, token: &str) -> Option<&'a str> {
    let mut args = line.split_whitespace();
    args.find(|&arg| arg == token)?;
    Some(args.next().unwrap_or(""))
}

struct MutableSource(Mutex<Vec<PodCaptureTarget>>);

impl PodCaptureSource for MutableSource {
    fn list_targets(&self) -> Vec<PodCaptureTarget> {
        self.0.lock().expect("source lock").clone()
    }
}

struct PartialCleanupBackend {
    fail_once: Mutex<HashSet<u64>>,
    cleaned: Mutex<Vec<u64>>,
}

impl NetnsUdpCleanupBackend for PartialCleanupBackend {
    fn netns_key(&self, target: &PodCaptureTarget) -> Result<u64, String> {
        target
            .cgroup_path
            .trim_start_matches("/cg/")
            .parse()
            .map_err(|_| "fixture netns is invalid".to_string())
    }

    fn cleanup_udp_capture(&self, _target: &PodCaptureTarget, expected_netns: u64) -> bool {
        if self
            .fail_once
            .lock()
            .expect("failure lock")
            .remove(&expected_netns)
        {
            return false;
        }
        self.cleaned
            .lock()
            .expect("cleaned lock")
            .push(expected_netns);
        true
    }
}

fn pod_target(uid: &str, netns: u64) -> PodCaptureTarget {
    PodCaptureTarget {
        pod_uid: uid.to_string(),
        cgroup_path: format!("/cg/{netns}"),
        source_identity: None,
        source_ips: PodCaptureSourceIps::default(),
    }
}

fn stable(target: UdpPlacement) -> UdpPlacementRequest {
    UdpPlacementRequest {
        phase: UdpMigrationPhase::Stable,
        target,
        generation: None,
        from: None,
        to: None,
        established: None,
        node: None,
        node_proof_generation: None,
    }
}

/// A release-level attestation with NO node-specific provenance. This is the
/// shape a bare `FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED=<target>` from a
/// client-render pipeline produces, and it must authorize nothing.
fn stable_attested(target: UdpPlacement, established: UdpPlacement) -> UdpPlacementRequest {
    UdpPlacementRequest {
        established: Some(established),
        ..stable(target)
    }
}

/// The Helm/GitOps-equivalent shape: release desired state PLUS this node's
/// identity and the release's node-proof generation.
fn stable_attested_on_node(
    target: UdpPlacement,
    established: UdpPlacement,
    node: &UdpNodeIdentity,
) -> UdpPlacementRequest {
    UdpPlacementRequest {
        node: Some(node.clone()),
        node_proof_generation: Some(PROOF_GENERATION.to_string()),
        ..stable_attested(target, established)
    }
}

fn stable_on_node(target: UdpPlacement, node: &UdpNodeIdentity) -> UdpPlacementRequest {
    UdpPlacementRequest {
        node: Some(node.clone()),
        node_proof_generation: Some(PROOF_GENERATION.to_string()),
        ..stable(target)
    }
}

/// Attach this node's identity to any request, exactly as the runtime does once
/// `FERRUM_K8S_NODE_UID` or the node-agent's published identity is resolvable.
/// A record that was written WITH an identity may only be read back by a
/// process that can still resolve one, so every migration phase acting on such
/// a record carries this.
fn on_node(request: UdpPlacementRequest, node: &UdpNodeIdentity) -> UdpPlacementRequest {
    UdpPlacementRequest {
        node: Some(node.clone()),
        node_proof_generation: Some(PROOF_GENERATION.to_string()),
        ..request
    }
}

fn transition(
    phase: UdpMigrationPhase,
    generation: &str,
    from: UdpPlacement,
    to: UdpPlacement,
) -> UdpPlacementRequest {
    UdpPlacementRequest {
        phase,
        target: to,
        generation: Some(generation.to_string()),
        from: Some(from),
        to: Some(to),
        established: None,
        node: None,
        node_proof_generation: None,
    }
}

fn cleanup_context(
    registry: &std::path::Path,
    request: &UdpPlacementRequest,
) -> ferrum_edge::proxy::udp_placement_migration::UdpMigrationContext {
    match prepare_placement(registry, request).expect("cleanup phase is admitted") {
        UdpPlacementDecision::RunCleanup(context) => context,
        UdpPlacementDecision::RunStable => panic!("cleanup must not run a producer"),
    }
}

fn publish_registry_proof(
    context: &ferrum_edge::proxy::udp_placement_migration::UdpMigrationContext,
) -> UdpRegistrySyncProof {
    publish_registry_proof_for_node(context, None)
}

/// Publish the node-agent's registry-synchronization marker, optionally bound to
/// the node UID that agent resolved authoritatively. The privileged preflight
/// requires that binding; the migration cleanup phase, which already decides
/// from durable node-bound ownership, does not.
fn publish_registry_proof_for_node(
    context: &ferrum_edge::proxy::udp_placement_migration::UdpMigrationContext,
    node_uid: Option<&str>,
) -> UdpRegistrySyncProof {
    assert_eq!(
        publish_registry_sync_marker_for_pods(
            context.registry_dir(),
            context.generation(),
            &HashSet::new(),
            node_uid,
        ),
        Ok(true)
    );
    context
        .registry_sync_proof()
        .expect("current registry publication proof")
}

fn complete_cleanup(context: &ferrum_edge::proxy::udp_placement_migration::UdpMigrationContext) {
    let proof = publish_registry_proof(context);
    context
        .mark_cleanup_complete(&proof)
        .expect("publish cleanup proof");
}

#[test]
fn direct_pod_to_host_flip_is_rejected_before_host_producer_admission() {
    let registry = tempfile::tempdir().expect("registry");
    assert!(matches!(
        prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns)),
        Ok(UdpPlacementDecision::RunStable)
    ));

    let error = prepare_placement(registry.path(), &stable(UdpPlacement::HostNetns))
        .err()
        .expect("unsafe direct flip must fail");
    assert!(error.contains("unsafe one-step"));
}

#[test]
fn legacy_or_fresh_host_placement_requires_explicit_cleanup_proof() {
    let registry = tempfile::tempdir().expect("registry");
    let error = prepare_placement(registry.path(), &stable(UdpPlacement::HostNetns))
        .err()
        .expect("host bootstrap without predecessor proof must fail");
    assert!(error.contains("no durable predecessor proof"));
}

#[test]
fn a_release_only_attestation_never_admits_a_recordless_same_boot_node() {
    // The pre-contract node from issue #3809: it stayed booted with live
    // workloads whose pod netns still redirect UDP to the retired predecessor
    // listener, and it missed both migration releases. The release ConfigMap
    // names no node, no incarnation, and no per-node cleanup result, so it
    // looks exactly like a rebooted node — and must authorize nothing.
    let registry = tempfile::tempdir().expect("registry");
    let error = prepare_placement(
        registry.path(),
        &stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns),
    )
    .err()
    .expect("release-only attestation must not admit a recordless node");
    assert!(error.contains("no node identity"), "{error}");
    assert_eq!(
        ferrum_edge::proxy::udp_placement_migration::snapshot().failure_reason,
        UdpMigrationFailureReason::NodeProofMissing
    );

    // Supplying node identity is still not proof: nothing on this node attests
    // that predecessor state was retired here.
    let node = identity(NODE_A, BOOT_1);
    let error = prepare_placement(
        registry.path(),
        &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
    )
    .err()
    .expect("a node with no cleanup attestation must be refused");
    assert!(
        error.contains("no node-specific cleanup attestation"),
        "{error}"
    );
    assert_eq!(
        ferrum_edge::proxy::udp_placement_migration::snapshot().failure_reason,
        UdpMigrationFailureReason::MigrationRequired
    );
    // Nothing was written, so the refusal is repeatable rather than a one-shot
    // that a restart could walk past.
    assert!(
        !registry
            .path()
            .join(".udp-placement-state-v1.json")
            .exists()
    );
}

#[test]
fn explicit_node_cleanup_proof_permits_the_host_placement() {
    let registry = tempfile::tempdir().expect("registry");
    let node = identity(NODE_A, BOOT_1);
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &node,
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
    let snapshot = ferrum_edge::proxy::udp_placement_migration::snapshot();
    assert_eq!(snapshot.adoption_proof, UdpAdoptionProof::NodeCleanup);
    assert!(snapshot.established_adoption);
    // The adoption is durable: a later restart resumes its own record.
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_on_node(UdpPlacement::HostNetns, &node)
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
}

#[test]
fn an_operator_exemption_is_node_bound_and_distinguishes_a_decommissioned_node() {
    let registry = tempfile::tempdir().expect("registry");
    let node = identity(NODE_A, BOOT_1);
    write_node_attestation(
        registry.path(),
        ".udp-placement-node-exempt",
        &node,
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
    assert_eq!(
        ferrum_edge::proxy::udp_placement_migration::snapshot().adoption_proof,
        UdpAdoptionProof::OperatorExempt
    );
}

#[test]
fn the_same_node_uid_after_a_reboot_adopts_but_a_reused_node_name_cannot() {
    // A persistent registry path keeps the durable record across a reboot. A
    // changed boot id proves every predecessor pod netns died with the previous
    // incarnation, so adoption is sound and is reported as `new_boot`.
    let registry = tempfile::tempdir().expect("registry");
    let first_boot = identity(NODE_A, BOOT_1);
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &first_boot,
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );
    prepare_placement(
        registry.path(),
        &stable_attested_on_node(
            UdpPlacement::HostNetns,
            UdpPlacement::HostNetns,
            &first_boot,
        ),
    )
    .expect("first-boot adoption");

    let second_boot = identity(NODE_A, BOOT_2);
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_on_node(UdpPlacement::HostNetns, &second_boot),
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
    assert_eq!(
        ferrum_edge::proxy::udp_placement_migration::snapshot().adoption_proof,
        UdpAdoptionProof::NewBoot
    );

    // The SAME node name rebuilt as a different machine carries a different
    // Kubernetes node UID and can never inherit that record.
    let other_machine = identity(NODE_B, BOOT_2);
    let error = prepare_placement(
        registry.path(),
        &stable_on_node(UdpPlacement::HostNetns, &other_machine),
    )
    .err()
    .expect("a different node UID must not inherit durable ownership");
    assert!(error.contains("different Kubernetes node UID"), "{error}");
    assert_eq!(
        ferrum_edge::proxy::udp_placement_migration::snapshot().failure_reason,
        UdpMigrationFailureReason::NodeIdentityMismatch
    );
}

#[test]
fn an_identity_bound_record_fails_closed_when_current_node_identity_is_unknown() {
    // The node-UID comparison is a boundary only while BOTH sides exist. If the
    // node-agent loses `nodes: get` (or the API server is unreachable) and no
    // FERRUM_K8S_NODE_UID was supplied, a restored/reused registry directory
    // carrying an identity-bound record would otherwise be trusted verbatim —
    // exactly the node-name-reuse inheritance the binding exists to refuse.
    let registry = tempfile::tempdir().expect("registry");
    let node = identity(NODE_A, BOOT_1);
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &node,
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );
    prepare_placement(
        registry.path(),
        &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
    )
    .expect("identity-bound adoption");

    // Every phase refuses, including the migration phases that would otherwise
    // adopt the record as a predecessor claim.
    for request in [
        stable(UdpPlacement::HostNetns),
        stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns),
        transition(
            UdpMigrationPhase::Cleanup,
            "unresolved-1",
            UdpPlacement::HostNetns,
            UdpPlacement::PodNetns,
        ),
        transition(
            UdpMigrationPhase::Finalize,
            "unresolved-1",
            UdpPlacement::HostNetns,
            UdpPlacement::PodNetns,
        ),
    ] {
        let error = prepare_placement(registry.path(), &request)
            .err()
            .expect("an identity-bound record must not be trusted without current identity");
        assert!(
            error.contains("current identity could not be resolved"),
            "{error}"
        );
        assert_eq!(
            ferrum_edge::proxy::udp_placement_migration::snapshot().failure_reason,
            UdpMigrationFailureReason::NodeIdentityUnresolved
        );
    }

    // A foreign node UID stays the harder mismatch refusal in every phase.
    let other_machine = identity(NODE_B, BOOT_1);
    for request in [
        stable_on_node(UdpPlacement::HostNetns, &other_machine),
        on_node(
            transition(
                UdpMigrationPhase::Cleanup,
                "unresolved-1",
                UdpPlacement::HostNetns,
                UdpPlacement::PodNetns,
            ),
            &other_machine,
        ),
        on_node(
            transition(
                UdpMigrationPhase::Finalize,
                "unresolved-1",
                UdpPlacement::HostNetns,
                UdpPlacement::PodNetns,
            ),
            &other_machine,
        ),
    ] {
        let error = prepare_placement(registry.path(), &request)
            .err()
            .expect("a foreign node UID must never inherit durable ownership");
        assert!(error.contains("different Kubernetes node UID"), "{error}");
        assert_eq!(
            ferrum_edge::proxy::udp_placement_migration::snapshot().failure_reason,
            UdpMigrationFailureReason::NodeIdentityMismatch
        );
    }

    // No refusal mutated anything: the owning node still resumes its record.
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_on_node(UdpPlacement::HostNetns, &node)
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
}

#[test]
fn an_unbound_durable_record_never_adopts_a_producer_placement() {
    // A durable record naming NO owning node UID proves nothing about which
    // machine established the placement it describes. That is the shape a
    // pre-#3809 record has, and also the shape a registry directory copied
    // between machines or reattached under a recycled node name presents — so
    // it must not start a producer merely by existing, with or without a
    // resolvable current identity (a missing identity is not a way past it).
    for node in [None, Some(identity(NODE_A, BOOT_1))] {
        let registry = tempfile::tempdir().expect("registry");
        write_unbound_state(registry.path(), UdpPlacement::PodNetns);
        let request = UdpPlacementRequest {
            node: node.clone(),
            node_proof_generation: node.as_ref().map(|_| PROOF_GENERATION.to_string()),
            ..stable(UdpPlacement::PodNetns)
        };
        let error = prepare_placement(registry.path(), &request)
            .err()
            .expect("unbound durable ownership must not adopt a producer");
        assert!(
            error.contains("names no owning Kubernetes node UID"),
            "{error}"
        );
        assert!(error.contains("cleanup then finalize"), "{error}");
    }

    // `disabled` owns no producer and carries no traffic, so it is the one
    // placement an unbound record may still carry — and the first start that
    // CAN resolve an identity binds it, so the boundary applies from then on.
    let registry = tempfile::tempdir().expect("registry");
    write_unbound_state(registry.path(), UdpPlacement::Disabled);
    assert!(matches!(
        prepare_placement(registry.path(), &stable(UdpPlacement::Disabled)),
        Ok(UdpPlacementDecision::RunStable)
    ));
    let node = identity(NODE_A, BOOT_1);
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_on_node(UdpPlacement::Disabled, &node)
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
    let error = prepare_placement(registry.path(), &stable(UdpPlacement::Disabled))
        .err()
        .expect("the bound record is identity-bound from here on");
    assert!(
        error.contains("current identity could not be resolved"),
        "{error}"
    );
}

#[test]
fn unbound_durable_ownership_recovers_only_through_cleanup_and_finalize() {
    // The supported recovery: an explicit cleanup migration retires the exact
    // Ferrum-owned predecessor state on this node, and finalize binds this
    // node's identity to the record it leaves behind. Only then does the
    // placement start.
    let registry = tempfile::tempdir().expect("registry");
    write_unbound_state(registry.path(), UdpPlacement::PodNetns);
    let node = identity(NODE_A, BOOT_1);

    let cleanup = on_node(
        transition(
            UdpMigrationPhase::Cleanup,
            "unbound-recovery",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
        &node,
    );
    let context = cleanup_context(registry.path(), &cleanup);
    complete_cleanup(&context);
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &on_node(
                transition(
                    UdpMigrationPhase::Finalize,
                    "unbound-recovery",
                    UdpPlacement::PodNetns,
                    UdpPlacement::HostNetns,
                ),
                &node,
            ),
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));

    // The recovered record is this node's own ownership from here on: it starts
    // without any node attestation, and it is refused for any other node.
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_on_node(UdpPlacement::HostNetns, &node)
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
    let error = prepare_placement(
        registry.path(),
        &stable_on_node(UdpPlacement::HostNetns, &identity(NODE_B, BOOT_1)),
    )
    .err()
    .expect("the recovered record is bound to the node that proved the cleanup");
    assert!(error.contains("different Kubernetes node UID"), "{error}");
}

/// The exact on-disk shape of ownership that names no node: a pre-#3809 record,
/// a restored backup, or a registry directory reattached under a reused node
/// name. Written directly so the refusal is decided by the record's CONTENT and
/// never by how this process happened to create it.
fn write_unbound_state(registry: &std::path::Path, active: UdpPlacement) {
    let document = serde_json::json!({
        "version": 1,
        "active": active.as_str(),
        "pending": null,
        "completed": null,
    });
    std::fs::write(
        registry.join(".udp-placement-state-v1.json"),
        serde_json::to_vec(&document).expect("encode durable state"),
    )
    .expect("write unbound durable state");
}

#[test]
fn a_stale_same_boot_node_identity_publication_would_inherit_the_predecessor_proof() {
    // The hazard the retraction closes, stated as a live fact: a publication
    // left by a PREVIOUS Kubernetes Node object on this same boot resolves —
    // its boot id IS the current incarnation's — and its UID matches the
    // predecessor's node-cleanup proof, so the host producer starts.
    let registry = tempfile::tempdir().expect("registry");
    let predecessor = identity(NODE_A, BOOT_1);
    publish_node_identity_for(registry.path(), &predecessor).expect("predecessor publication");
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &predecessor,
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );

    let resolved = UdpNodeIdentity::resolve_published(registry.path(), BOOT_1);
    assert_eq!(resolved.as_ref(), Some(&predecessor));
    let request = UdpPlacementRequest {
        node: resolved,
        node_proof_generation: Some(PROOF_GENERATION.to_string()),
        ..stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns)
    };
    assert!(matches!(
        prepare_placement(registry.path(), &request),
        Ok(UdpPlacementDecision::RunStable)
    ));
}

#[test]
fn retracting_the_publication_leaves_no_stale_identity_authorizing_adoption() {
    // The publisher retracts BEFORE anything that can fail, and again after a
    // failure, so a lookup/publication failure leaves NO identity rather than
    // the predecessor Node object's UID.
    let registry = tempfile::tempdir().expect("registry");
    let predecessor = identity(NODE_A, BOOT_1);
    let identity_file = registry.path().join(".node-identity-v1.json");
    publish_node_identity_for(registry.path(), &predecessor).expect("predecessor publication");
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &predecessor,
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );

    retract_node_identity(registry.path()).expect("retraction");
    assert!(
        !identity_file.exists(),
        "the exact publication must be gone, not merely superseded"
    );
    assert_eq!(
        UdpNodeIdentity::resolve_published(registry.path(), BOOT_1),
        None
    );
    // Retraction is idempotent, so the post-failure re-assertion is safe.
    retract_node_identity(registry.path()).expect("idempotent retraction");

    // With no identity resolved, the predecessor's proof authorizes nothing.
    let error = prepare_placement(
        registry.path(),
        &stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns),
    )
    .err()
    .expect("a retracted identity must not adopt the host producer");
    assert!(error.contains("no node identity"), "{error}");

    // The replacement Node object publishes its OWN UID, which the predecessor
    // proof cannot satisfy.
    let replacement = identity(NODE_B, BOOT_1);
    publish_node_identity_for(registry.path(), &replacement).expect("replacement publication");
    let resolved = UdpNodeIdentity::resolve_published(registry.path(), BOOT_1);
    assert_eq!(resolved.as_ref(), Some(&replacement));
    let request = UdpPlacementRequest {
        node: resolved,
        node_proof_generation: Some(PROOF_GENERATION.to_string()),
        ..stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns)
    };
    let error = prepare_placement(registry.path(), &request)
        .err()
        .expect("a recreated node must not inherit the predecessor's proof");
    assert!(error.contains("different Kubernetes node UID"), "{error}");
}

#[cfg(unix)]
#[test]
fn identity_retraction_is_narrow_and_does_not_follow_symlinks() {
    use std::os::unix::fs::symlink;

    let registry = tempfile::tempdir().expect("registry");
    let published = registry.path().join(".node-identity-v1.json");
    let outside = registry.path().join("outside-target");
    std::fs::write(&outside, b"must survive").expect("symlink target");
    symlink(&outside, &published).expect("symlinked identity");
    let neighbour = registry.path().join(".udp-node-cleanup-proof-v1.json");
    std::fs::write(&neighbour, b"neighbour").expect("neighbouring artifact");

    retract_node_identity(registry.path()).expect("symlinked publication is retracted");
    assert!(
        published.symlink_metadata().is_err(),
        "the link itself must be unlinked"
    );
    assert_eq!(
        std::fs::read(&outside).expect("symlink target survives"),
        b"must survive"
    );
    assert!(
        neighbour.exists(),
        "retraction must touch only the identity publication"
    );

    // A crash-left or hostile entry of another type is retracted, not skipped.
    std::fs::create_dir(&published).expect("directory at the publication path");
    retract_node_identity(registry.path()).expect("directory publication is retracted");
    assert!(!published.exists());
}

#[test]
fn a_node_attestation_from_another_node_or_boot_or_generation_is_refused() {
    let node = identity(NODE_A, BOOT_1);

    // Another machine's proof, copied onto this node.
    let registry = tempfile::tempdir().expect("registry");
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &identity(NODE_B, BOOT_1),
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );
    let error = prepare_placement(
        registry.path(),
        &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
    )
    .err()
    .expect("another node's attestation must be refused");
    assert!(error.contains("different Kubernetes node UID"), "{error}");

    // This node's proof, but from an earlier incarnation: a same-boot
    // pre-contract node could have installed predecessor rules since.
    let registry = tempfile::tempdir().expect("registry");
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &identity(NODE_A, BOOT_2),
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );
    let error = prepare_placement(
        registry.path(),
        &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
    )
    .err()
    .expect("an earlier incarnation's attestation must be refused");
    assert!(error.contains("earlier boot"), "{error}");

    // A superseded node-proof generation: the migration moved on.
    let registry = tempfile::tempdir().expect("registry");
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &node,
        UdpPlacement::HostNetns,
        "stale-generation",
    );
    let error = prepare_placement(
        registry.path(),
        &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
    )
    .err()
    .expect("a stale node-proof generation must be refused");
    assert!(
        error.contains("superseded node-proof generation"),
        "{error}"
    );
    assert_eq!(
        ferrum_edge::proxy::udp_placement_migration::snapshot().failure_reason,
        UdpMigrationFailureReason::GenerationMismatch
    );

    // A proof for a different incoming placement proves nothing about this one.
    let registry = tempfile::tempdir().expect("registry");
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &node,
        UdpPlacement::PodNetns,
        PROOF_GENERATION,
    );
    let error = prepare_placement(
        registry.path(),
        &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
    )
    .err()
    .expect("a proof for another placement must be refused");
    assert!(error.contains("different incoming placement"), "{error}");
}

#[test]
fn malformed_or_unreadable_node_proof_fails_closed() {
    let node = identity(NODE_A, BOOT_1);
    for body in [
        &b"{"[..],
        &b"{\"version\":2,\"node\":{\"node_uid\":\"a\",\"boot_id\":\"b\"},\"target\":\"host-netns\",\"generation\":\"g\"}"[..],
        &vec![b'x'; 4096][..],
    ] {
        let registry = tempfile::tempdir().expect("registry");
        std::fs::write(
            registry.path().join(".udp-node-cleanup-proof-v1.json"),
            body,
        )
        .expect("write hostile attestation");
        let error = prepare_placement(
            registry.path(),
            &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
        )
        .err()
        .expect("unreadable or malformed proof must fail closed");
        assert!(error.contains("node-specific"), "{error}");
        assert!(
            !registry
                .path()
                .join(".udp-placement-state-v1.json")
                .exists()
        );
    }
}

#[test]
fn a_release_without_a_node_proof_generation_cannot_bind_any_proof() {
    let registry = tempfile::tempdir().expect("registry");
    let node = identity(NODE_A, BOOT_1);
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &node,
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );
    let request = UdpPlacementRequest {
        node: Some(node),
        node_proof_generation: None,
        ..stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns)
    };
    let error = prepare_placement(registry.path(), &request)
        .err()
        .expect("a release with no node-proof generation must refuse");
    assert!(error.contains("no node-proof generation"), "{error}");
}

#[test]
fn a_cleanup_complete_node_that_missed_finalize_still_resumes_through_finalize() {
    // Node-specific proof is additive to the existing generation-safe
    // resumption, never a replacement for it: a node that persisted cleanup
    // completion and then lost its finalize release must still refuse `stable`
    // and finalize on the exact same tuple.
    let registry = tempfile::tempdir().expect("registry");
    let node = identity(NODE_A, BOOT_1);
    prepare_placement(
        registry.path(),
        &stable_on_node(UdpPlacement::PodNetns, &node),
    )
    .expect("pod placement bootstrap");
    let cleanup = on_node(
        transition(
            UdpMigrationPhase::Cleanup,
            "resume-1",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
        &node,
    );
    let context = cleanup_context(registry.path(), &cleanup);
    complete_cleanup(&context);

    let error = prepare_placement(
        registry.path(),
        &stable_on_node(UdpPlacement::HostNetns, &node),
    )
    .err()
    .expect("a cleanup-complete node must not start stable");
    assert!(error.contains("phase=finalize"), "{error}");

    let finalize = on_node(
        transition(
            UdpMigrationPhase::Finalize,
            "resume-1",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
        &node,
    );
    assert!(matches!(
        prepare_placement(registry.path(), &finalize),
        Ok(UdpPlacementDecision::RunStable)
    ));
    // The finalized record is this node's own proof from here on: no node
    // attestation is consulted, because the record is present.
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_on_node(UdpPlacement::HostNetns, &node)
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
}

#[test]
fn established_attestation_cannot_authorize_an_in_place_flip_or_a_mismatch() {
    let registry = tempfile::tempdir().expect("registry");
    prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .expect("pod placement bootstrap");
    // A PRESENT durable record is never overridden by the attestation.
    let error = prepare_placement(
        registry.path(),
        &stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns),
    )
    .err()
    .expect("attested in-place flip must still fail");
    assert!(error.contains("unsafe one-step"));

    // An attestation naming a different placement proves nothing about this one.
    let fresh = tempfile::tempdir().expect("fresh registry");
    let error = prepare_placement(
        fresh.path(),
        &stable_attested(UdpPlacement::HostNetns, UdpPlacement::PodNetns),
    )
    .err()
    .expect("mismatched attestation must fail");
    assert!(error.contains("no durable predecessor proof"));
}

#[test]
fn quarantine_tombstone_refuses_attested_adoption_until_finalize_clears_it() {
    let registry = tempfile::tempdir().expect("registry");
    std::fs::write(registry.path().join(".udp-placement-quarantined"), b"")
        .expect("quarantine tombstone");
    let attested = stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns);
    let error = prepare_placement(registry.path(), &attested)
        .err()
        .expect("quarantined ownership must refuse adoption");
    assert!(error.contains("quarantined"));
    // Every placement is refused, not just the attested host one: the operator
    // quarantined ownership precisely because it is unknown.
    let error = prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .err()
        .expect("quarantined ownership must refuse any absent-state bootstrap");
    assert!(error.contains("quarantined"));

    // Only a proven cleanup/finalize pair clears the quarantine. Finalize is
    // where node ownership is asserted, so it carries this node's identity.
    let node = identity(NODE_A, BOOT_1);
    let cleanup = on_node(
        transition(
            UdpMigrationPhase::Cleanup,
            "repair-1",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
        &node,
    );
    let context = cleanup_context(registry.path(), &cleanup);
    complete_cleanup(&context);
    let repair_finalize = on_node(
        transition(
            UdpMigrationPhase::Finalize,
            "repair-1",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
        &node,
    );
    assert!(matches!(
        prepare_placement(registry.path(), &repair_finalize),
        Ok(UdpPlacementDecision::RunStable)
    ));
    assert!(
        !registry.path().join(".udp-placement-quarantined").exists(),
        "finalize proof must clear the quarantine tombstone"
    );

    // Model a crash or transient removal failure after the durable finalize
    // state was written. An idempotent finalize retry must retry its cleanup
    // side effect instead of returning early and stranding the marker.
    std::fs::create_dir(registry.path().join(".udp-placement-quarantined"))
        .expect("empty directory tombstone");
    assert!(matches!(
        prepare_placement(registry.path(), &repair_finalize),
        Ok(UdpPlacementDecision::RunStable)
    ));
    assert!(
        !registry.path().join(".udp-placement-quarantined").exists(),
        "idempotent finalize must retry safe tombstone removal"
    );
}

#[test]
fn pod_to_host_cleanup_resumes_and_finalize_requires_durable_completion() {
    let registry = tempfile::tempdir().expect("registry");
    // Ownership of a producer placement is identity-bound end to end, so every
    // phase of this rollout carries the same node identity.
    let node = identity(NODE_A, BOOT_1);
    prepare_placement(
        registry.path(),
        &stable_on_node(UdpPlacement::PodNetns, &node),
    )
    .expect("pod placement bootstrap");
    let cleanup = on_node(
        transition(
            UdpMigrationPhase::Cleanup,
            "rollout-42",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
        &node,
    );
    let first = cleanup_context(registry.path(), &cleanup);
    let resumed = cleanup_context(registry.path(), &cleanup);
    assert_eq!(first.generation(), resumed.generation());

    let finalize = on_node(
        transition(
            UdpMigrationPhase::Finalize,
            "rollout-42",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
        &node,
    );
    assert!(prepare_placement(registry.path(), &finalize).is_err());
    complete_cleanup(&resumed);
    let completed_restart = cleanup_context(registry.path(), &cleanup);
    assert_eq!(completed_restart.generation(), "rollout-42");
    assert!(matches!(
        prepare_placement(registry.path(), &finalize),
        Ok(UdpPlacementDecision::RunStable)
    ));
    assert!(matches!(
        prepare_placement(registry.path(), &finalize),
        Ok(UdpPlacementDecision::RunStable)
    ));
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_on_node(UdpPlacement::HostNetns, &node)
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
}

#[test]
fn crash_leftover_temporary_files_do_not_block_exact_tuple_resume() {
    let registry = tempfile::tempdir().expect("registry");
    prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .expect("bootstrap placement");
    let crashed_temp = registry
        .path()
        .join(".udp-placement-state-v1.json.tmp.crashed");
    std::fs::write(&crashed_temp, b"incomplete").expect("crash leftover");
    age_crash_temp(&crashed_temp);
    let cleanup = transition(
        UdpMigrationPhase::Cleanup,
        "crash-resume",
        UdpPlacement::PodNetns,
        UdpPlacement::HostNetns,
    );
    let context = cleanup_context(registry.path(), &cleanup);
    assert_eq!(context.generation(), "crash-resume");
    assert!(context.cleanup_pod_netns());
    assert!(!context.cleanup_host_netns());
    assert!(
        !crashed_temp.exists(),
        "the next state publication must reap an owned exact-prefix crash temp"
    );
}

#[test]
fn marker_publication_reaps_only_owned_exact_prefix_temporary_files() {
    let registry = tempfile::tempdir().expect("registry");
    let owned = registry.path().join(".udp-registry-synced.tmp.crashed");
    let fresh = registry.path().join(".udp-registry-synced.tmp.active");
    let foreign_prefix = registry.path().join(".udp-registry-synced.other");
    std::fs::write(&owned, b"partial").expect("owned temp");
    age_crash_temp(&owned);
    std::fs::write(&fresh, b"in progress").expect("fresh temp");
    std::fs::write(&foreign_prefix, b"foreign").expect("foreign file");

    assert_eq!(
        publish_registry_sync_marker_for_pods(registry.path(), "temp-reap", &HashSet::new(), None),
        Ok(true)
    );
    assert!(!owned.exists());
    assert!(fresh.exists());
    assert!(foreign_prefix.exists());
}

#[cfg(unix)]
#[test]
fn marker_temp_reaper_refuses_symlinks_and_directories() {
    use std::os::unix::fs::symlink;

    let registry = tempfile::tempdir().expect("registry");
    let foreign = registry.path().join("foreign-target");
    let symlink_temp = registry.path().join(".udp-registry-synced.tmp.symlink");
    let directory_temp = registry.path().join(".udp-registry-synced.tmp.directory");
    std::fs::write(&foreign, b"foreign").expect("foreign target");
    symlink(&foreign, &symlink_temp).expect("symlink temp");
    std::fs::create_dir(&directory_temp).expect("directory temp");

    assert_eq!(
        publish_registry_sync_marker_for_pods(
            registry.path(),
            "temp-reap-safe",
            &HashSet::new(),
            None,
        ),
        Ok(true)
    );
    assert!(symlink_temp.symlink_metadata().is_ok());
    assert!(directory_temp.is_dir());
    assert_eq!(
        std::fs::read(&foreign).expect("foreign survives"),
        b"foreign"
    );
}

#[test]
fn malformed_or_non_regular_durable_state_fails_closed() {
    let registry = tempfile::tempdir().expect("registry");
    let state = registry.path().join(".udp-placement-state-v1.json");
    std::fs::create_dir(&state).expect("non-regular state fixture");
    let error = prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .err()
        .expect("non-regular state must not be guessed");
    assert!(error.contains("securely open"));

    std::fs::remove_dir(&state).expect("remove non-regular state");
    std::fs::write(&state, b"{\"version\":1").expect("truncated state fixture");
    let error = prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .err()
        .expect("truncated state must not be guessed");
    assert!(error.contains("malformed"));

    std::fs::write(
        &state,
        br#"{"version":2,"active":"pod-netns","pending":null,"completed":null}"#,
    )
    .expect("unsupported state fixture");
    let error = prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .err()
        .expect("unsupported state must not be guessed");
    assert!(error.contains("unsupported version"));
}

#[test]
fn semantically_inconsistent_durable_state_fails_closed() {
    let registry = tempfile::tempdir().expect("registry");
    let state = registry.path().join(".udp-placement-state-v1.json");
    std::fs::write(
        state,
        br#"{"version":1,"active":"pod-netns","pending":null,"completed":{"generation":"completed-host","from":"pod-netns","to":"host-netns"}}"#,
    )
    .expect("inconsistent state fixture");

    let error = prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .err()
        .expect("inconsistent completed ownership must not admit a producer");
    assert!(error.contains("inconsistent completed ownership"));
}

#[cfg(unix)]
#[test]
fn linked_durable_state_is_rejected_without_guessing_ownership() {
    let registry = tempfile::tempdir().expect("registry");
    let source = registry.path().join("state-source");
    let state = registry.path().join(".udp-placement-state-v1.json");
    std::fs::write(
        &source,
        br#"{"version":1,"active":"pod-netns","pending":null,"completed":null}"#,
    )
    .expect("linked state source");
    std::fs::hard_link(&source, &state).expect("hard-linked state fixture");

    let error = prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .err()
        .expect("multiply-linked state must not be guessed");
    assert!(error.contains("singly linked"));
}

#[test]
fn pre_contract_cleanup_retires_both_domains_and_persists_that_scope() {
    let registry = tempfile::tempdir().expect("registry");
    let cleanup = transition(
        UdpMigrationPhase::Cleanup,
        "legacy-host-pod",
        UdpPlacement::HostNetns,
        UdpPlacement::PodNetns,
    );
    let first = cleanup_context(registry.path(), &cleanup);
    assert!(first.cleanup_pod_netns());
    assert!(first.cleanup_host_netns());
    let resumed = cleanup_context(registry.path(), &cleanup);
    assert!(resumed.cleanup_pod_netns());
    assert!(resumed.cleanup_host_netns());
}

#[test]
fn host_to_pod_cleanup_and_finalize_are_symmetric() {
    let registry = tempfile::tempdir().expect("registry");
    // Both directions land on a producer placement, so every phase carries this
    // node's identity: finalize refuses to leave a producer-owning record that
    // names no owning node UID.
    let node = identity(NODE_A, BOOT_1);
    let bootstrap_cleanup = on_node(
        transition(
            UdpMigrationPhase::Cleanup,
            "host-bootstrap",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
        &node,
    );
    let context = cleanup_context(registry.path(), &bootstrap_cleanup);
    complete_cleanup(&context);
    prepare_placement(
        registry.path(),
        &on_node(
            transition(
                UdpMigrationPhase::Finalize,
                "host-bootstrap",
                UdpPlacement::PodNetns,
                UdpPlacement::HostNetns,
            ),
            &node,
        ),
    )
    .expect("host bootstrap finalize");

    let reverse = on_node(
        transition(
            UdpMigrationPhase::Cleanup,
            "reverse-7",
            UdpPlacement::HostNetns,
            UdpPlacement::PodNetns,
        ),
        &node,
    );
    let context = cleanup_context(registry.path(), &reverse);
    assert!(
        prepare_placement(
            registry.path(),
            &stable_on_node(UdpPlacement::PodNetns, &node)
        )
        .is_err()
    );
    complete_cleanup(&context);
    prepare_placement(
        registry.path(),
        &on_node(
            transition(
                UdpMigrationPhase::Finalize,
                "reverse-7",
                UdpPlacement::HostNetns,
                UdpPlacement::PodNetns,
            ),
            &node,
        ),
    )
    .expect("reverse finalize");
}

#[test]
fn enabled_disabled_transitions_also_require_cleanup_and_finalize() {
    for (from, to, generation) in [
        (
            UdpPlacement::PodNetns,
            UdpPlacement::Disabled,
            "disable-pod",
        ),
        (
            UdpPlacement::Disabled,
            UdpPlacement::HostNetns,
            "enable-host",
        ),
        (
            UdpPlacement::HostNetns,
            UdpPlacement::Disabled,
            "disable-host",
        ),
        (UdpPlacement::Disabled, UdpPlacement::PodNetns, "enable-pod"),
    ] {
        let registry = tempfile::tempdir().expect("registry");
        // Ownership of a producer placement is identity-bound end to end, so
        // every phase in this rollout carries the same node identity.
        let node = identity(NODE_A, BOOT_1);
        if from == UdpPlacement::HostNetns {
            let bootstrap = cleanup_context(
                registry.path(),
                &on_node(
                    transition(
                        UdpMigrationPhase::Cleanup,
                        "bootstrap-host",
                        UdpPlacement::PodNetns,
                        UdpPlacement::HostNetns,
                    ),
                    &node,
                ),
            );
            complete_cleanup(&bootstrap);
            prepare_placement(
                registry.path(),
                &on_node(
                    transition(
                        UdpMigrationPhase::Finalize,
                        "bootstrap-host",
                        UdpPlacement::PodNetns,
                        UdpPlacement::HostNetns,
                    ),
                    &node,
                ),
            )
            .expect("bootstrap finalize");
        } else {
            prepare_placement(registry.path(), &stable_on_node(from, &node))
                .expect("bootstrap placement");
        }
        assert!(prepare_placement(registry.path(), &stable_on_node(to, &node)).is_err());
        let context = cleanup_context(
            registry.path(),
            &on_node(
                transition(UdpMigrationPhase::Cleanup, generation, from, to),
                &node,
            ),
        );
        complete_cleanup(&context);
        prepare_placement(
            registry.path(),
            &on_node(
                transition(UdpMigrationPhase::Finalize, generation, from, to),
                &node,
            ),
        )
        .expect("finalize transition");
        assert!(matches!(
            prepare_placement(registry.path(), &stable_on_node(to, &node)),
            Ok(UdpPlacementDecision::RunStable)
        ));
    }
}

#[test]
fn interrupted_cleanup_rejects_stale_generation_and_predecessor() {
    let registry = tempfile::tempdir().expect("registry");
    let node = identity(NODE_A, BOOT_1);
    prepare_placement(
        registry.path(),
        &stable_on_node(UdpPlacement::PodNetns, &node),
    )
    .expect("bootstrap placement");
    cleanup_context(
        registry.path(),
        &on_node(
            transition(
                UdpMigrationPhase::Cleanup,
                "owned-generation",
                UdpPlacement::PodNetns,
                UdpPlacement::HostNetns,
            ),
            &node,
        ),
    );
    let error = prepare_placement(
        registry.path(),
        &on_node(
            transition(
                UdpMigrationPhase::Cleanup,
                "stale-generation",
                UdpPlacement::PodNetns,
                UdpPlacement::HostNetns,
            ),
            &node,
        ),
    )
    .err()
    .expect("a different generation must not adopt the pending migration");
    assert!(error.contains("already pending"), "{error}");
    let error = prepare_placement(
        registry.path(),
        &on_node(
            transition(
                UdpMigrationPhase::Finalize,
                "owned-generation",
                UdpPlacement::HostNetns,
                UdpPlacement::PodNetns,
            ),
            &node,
        ),
    )
    .err()
    .expect("a reversed predecessor must not finalize the pending migration");
    assert!(
        error.contains("does not match durable cleanup ownership"),
        "{error}"
    );
}

#[test]
fn completed_generation_cannot_authorize_a_later_cleanup_transition() {
    let registry = tempfile::tempdir().expect("registry");
    let node = identity(NODE_A, BOOT_1);
    prepare_placement(
        registry.path(),
        &stable_on_node(UdpPlacement::PodNetns, &node),
    )
    .expect("bootstrap placement");
    let first = on_node(
        transition(
            UdpMigrationPhase::Cleanup,
            "generation-once",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
        &node,
    );
    complete_cleanup(&cleanup_context(registry.path(), &first));
    prepare_placement(
        registry.path(),
        &on_node(
            transition(
                UdpMigrationPhase::Finalize,
                "generation-once",
                UdpPlacement::PodNetns,
                UdpPlacement::HostNetns,
            ),
            &node,
        ),
    )
    .expect("first finalize");

    let error = prepare_placement(
        registry.path(),
        &on_node(
            transition(
                UdpMigrationPhase::Cleanup,
                "generation-once",
                UdpPlacement::HostNetns,
                UdpPlacement::PodNetns,
            ),
            &node,
        ),
    )
    .err()
    .expect("a completed generation must not bind a later registry proof");
    assert!(error.contains("already completed"));
}

#[test]
fn registry_relist_ack_is_bound_to_generation_and_retracted_on_restart() {
    let registry = tempfile::tempdir().expect("registry");
    let context = cleanup_context(
        registry.path(),
        &transition(
            UdpMigrationPhase::Cleanup,
            "generation-a",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
    );
    assert!(context.registry_sync_proof().is_none());
    assert_eq!(
        publish_registry_sync_marker_for_pods(
            registry.path(),
            "generation-b",
            &HashSet::new(),
            None,
        ),
        Ok(true)
    );
    assert!(context.registry_sync_proof().is_none());
    assert_eq!(
        publish_registry_sync_marker_for_pods(
            registry.path(),
            "generation-a",
            &HashSet::new(),
            None,
        ),
        Ok(true)
    );
    assert!(context.registry_sync_proof().is_some());
    clear_registry_sync_marker(registry.path()).expect("restart retraction");
    assert!(context.registry_sync_proof().is_none());
}

#[test]
fn same_generation_registry_republication_has_a_distinct_proof() {
    let registry = tempfile::tempdir().expect("registry");
    let context = cleanup_context(
        registry.path(),
        &transition(
            UdpMigrationPhase::Cleanup,
            "generation-a",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
    );
    let first = publish_registry_proof(&context);
    let second = publish_registry_proof(&context);
    assert!(
        first != second,
        "each publication must identify a new registry snapshot even for the same generation"
    );
}

#[test]
fn registry_proof_change_resets_repeated_passes_and_blocks_finalize() {
    let registry = tempfile::tempdir().expect("registry");
    let node = identity(NODE_A, BOOT_1);
    prepare_placement(
        registry.path(),
        &stable_on_node(UdpPlacement::PodNetns, &node),
    )
    .expect("bootstrap placement");
    let cleanup = on_node(
        transition(
            UdpMigrationPhase::Cleanup,
            "generation-a",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
        &node,
    );
    let context = cleanup_context(registry.path(), &cleanup);
    let first_proof = publish_registry_proof(&context);
    let mut window = UdpCleanupProofWindow::new(true, true);
    let first_pass = window.observe_pass(
        Some(first_proof.clone()),
        Some(first_proof.clone()),
        true,
        Some(7),
    );
    assert!(!first_pass.host_complete());
    assert!(!first_pass.pod_complete());

    let replacement_proof = publish_registry_proof(&context);
    let changed_pass = window.observe_pass(
        Some(first_proof.clone()),
        Some(replacement_proof.clone()),
        true,
        Some(7),
    );
    assert!(!changed_pass.proof_is_valid());
    let first_replacement_pass = window.observe_pass(
        Some(replacement_proof.clone()),
        Some(replacement_proof),
        true,
        Some(7),
    );
    assert!(!first_replacement_pass.host_complete());
    assert!(!first_replacement_pass.pod_complete());
    assert!(context.mark_cleanup_complete(&first_proof).is_err());

    let finalize = on_node(
        transition(
            UdpMigrationPhase::Finalize,
            "generation-a",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
        &node,
    );
    let error = prepare_placement(registry.path(), &finalize)
        .err()
        .expect("finalize must refuse without durable cleanup completion");
    assert!(error.contains("not durably complete"), "{error}");
}

#[test]
fn registry_relist_ack_requires_every_expected_pod_entry() {
    let registry = tempfile::tempdir().expect("registry");
    let expected = HashSet::from(["pod-a".to_string(), "pod-b".to_string()]);
    std::fs::write(registry.path().join("pod-a"), b"/cg/1\n").expect("first pod entry");
    assert_eq!(
        publish_registry_sync_marker_for_pods(registry.path(), "generation-a", &expected, None),
        Ok(false)
    );
    assert!(!registry.path().join(".udp-registry-synced").exists());

    std::fs::write(registry.path().join("pod-b"), b"/cg/2\n").expect("second pod entry");
    assert_eq!(
        publish_registry_sync_marker_for_pods(registry.path(), "generation-a", &expected, None),
        Ok(true)
    );
    assert!(registry.path().join(".udp-registry-synced").is_file());
}

#[tokio::test]
async fn partial_pod_cleanup_retries_and_pod_churn_invalidates_completion_snapshot() {
    let source = Arc::new(MutableSource(Mutex::new(vec![
        pod_target("pod-a", 1),
        pod_target("pod-b", 2),
    ])));
    let backend = PartialCleanupBackend {
        fail_once: Mutex::new(HashSet::from([2])),
        cleaned: Mutex::new(Vec::new()),
    };
    let mut manager =
        NetnsUdpCleanupManager::new(source.clone(), backend, std::time::Duration::from_secs(2));

    let partial = manager.migration_cleanup_once().await;
    assert_eq!(partial.outstanding, 1);
    assert_eq!(
        partial.failure_reason,
        Some(UdpMigrationFailureReason::PodCleanupFailed)
    );
    let complete = manager.migration_cleanup_once().await;
    assert_eq!(complete.outstanding, 0);
    assert_eq!(complete.failure_reason, None);

    source
        .0
        .lock()
        .expect("source lock")
        .push(pod_target("pod-c", 3));
    let churned = manager.migration_cleanup_once().await;
    assert_eq!(churned.outstanding, 0);
    assert_ne!(
        churned.registry_fingerprint, complete.registry_fingerprint,
        "the supervisor's repeated-pass proof must restart when a pod appears"
    );
}

#[tokio::test]
async fn malformed_registry_entry_blocks_migration_cleanup_proof() {
    let registry = tempfile::tempdir().expect("registry");
    std::fs::write(registry.path().join("pod-a"), b"").expect("malformed entry");
    let source = DirectoryCaptureSource::new(registry.path());
    assert!(source.list_targets().is_empty());
    assert!(source.list_complete_targets().is_err());
    let source = Arc::new(source);
    let backend = PartialCleanupBackend {
        fail_once: Mutex::new(HashSet::new()),
        cleaned: Mutex::new(Vec::new()),
    };
    let mut manager =
        NetnsUdpCleanupManager::new(source, backend, std::time::Duration::from_secs(2));

    let blocked = manager.migration_cleanup_once().await;
    assert_eq!(blocked.outstanding, 1);
    assert_eq!(
        blocked.failure_reason,
        Some(UdpMigrationFailureReason::RegistryNotSynchronized)
    );
    std::fs::write(registry.path().join("pod-a"), b"/cg/1\n").expect("repaired entry");
    let complete = manager.migration_cleanup_once().await;
    assert_eq!(complete.outstanding, 0);
    assert_eq!(complete.failure_reason, None);
}

#[tokio::test]
async fn stale_gate_ack_cannot_authorize_migration_cleanup() {
    let source = Arc::new(MutableSource(Mutex::new(vec![pod_target("pod-a", 1)])));
    let backend = PartialCleanupBackend {
        fail_once: Mutex::new(HashSet::new()),
        cleaned: Mutex::new(Vec::new()),
    };
    let registry = tempfile::tempdir().expect("registry");
    let ready_dir = registry.path().join(".udp-ready");
    let ack_dir = registry.path().join(".udp-not-ready");
    std::fs::create_dir_all(&ready_dir).expect("ready dir");
    std::fs::create_dir_all(&ack_dir).expect("ack dir");
    std::fs::write(ready_dir.join("pod-a"), b"").expect("ready marker");
    std::fs::write(ack_dir.join("pod-a"), b"stale").expect("stale ack");
    let mut manager =
        NetnsUdpCleanupManager::new(source, backend, std::time::Duration::from_secs(2))
            .with_ready_dir(Some(ready_dir));

    let blocked = manager.migration_cleanup_once().await;
    assert_eq!(blocked.outstanding, 1);
    assert_eq!(
        blocked.failure_reason,
        Some(UdpMigrationFailureReason::GateAcknowledgementMissing)
    );
    assert!(!ack_dir.join("pod-a").exists());
    std::fs::write(ack_dir.join("pod-a"), b"").expect("fresh ack");
    let complete = manager.migration_cleanup_once().await;
    assert_eq!(complete.outstanding, 0);
    assert_eq!(complete.failure_reason, None);
}

#[test]
fn the_node_preflight_retires_both_placements_for_ipv4_and_ipv6() {
    // A recordless node cannot know which placement ran here before, so it must
    // not guess: the preflight context declares the conservative `disabled`
    // predecessor, which reaps BOTH ownership domains.
    let registry = tempfile::tempdir().expect("registry");
    let context =
        ferrum_edge::proxy::udp_placement_migration::UdpMigrationContext::for_node_preflight(
            registry.path(),
            UdpPlacement::HostNetns,
            identity(NODE_A, BOOT_1),
            PROOF_GENERATION,
        )
        .expect("node preflight context");
    assert!(context.is_node_preflight());
    assert!(
        context.cleanup_pod_netns(),
        "pod-netns ownership must be reaped"
    );
    assert!(
        context.cleanup_host_netns(),
        "host-netns ownership must be reaped"
    );
    assert_eq!(context.to(), UdpPlacement::HostNetns);
    assert_eq!(context.generation(), PROOF_GENERATION);

    // Both the pod-netns and the host-netns retirement scripts delete the exact
    // Ferrum-owned objects in BOTH address families, and neither flushes a
    // table nor matches a chain by pattern.
    let pod = ferrum_edge::capture::IptablesPlan::udp_teardown_script(true);
    let host = ferrum_edge::capture::IptablesPlan::host_udp_teardown_script();
    for script in [&pod, &host] {
        assert!(script.contains("iptables"), "{script}");
        // Ownership safety: every chain flush/delete names a Ferrum-owned
        // chain from the closed inventory below. A bare table flush would take
        // a co-resident CNI's rules down with it, so it must never appear.
        // `FERRUM_UDP_FAIL_CLOSED_{A,B}` are the pod-netns alternating DROP
        // guards — exact Ferrum-owned names, not a `FERRUM_MESH_UDP_*` prefix.
        for line in script.lines() {
            for token in ["-F", "-X"] {
                if let Some(chain) = chain_named_by_flush_or_delete(line, token) {
                    assert!(
                        is_ferrum_owned_udp_teardown_chain(chain),
                        "{token} must name a Ferrum-owned chain, got {chain:?} in {line}"
                    );
                }
            }
        }
    }
    assert!(
        pod.contains("FERRUM_UDP_FAIL_CLOSED_A") && pod.contains("FERRUM_UDP_FAIL_CLOSED_B"),
        "pod teardown must reap both fail-closed guard generations: {pod}"
    );
    assert!(
        pod.contains("ip6tables"),
        "pod teardown must cover IPv6: {pod}"
    );
    assert!(
        host.contains("ip6tables"),
        "host teardown must cover IPv6: {host}"
    );

    // A `disabled` target has no incoming placement to prove, so it is refused
    // rather than publishing a vacuous attestation.
    assert!(
        ferrum_edge::proxy::udp_placement_migration::UdpMigrationContext::for_node_preflight(
            registry.path(),
            UdpPlacement::Disabled,
            identity(NODE_A, BOOT_1),
            PROOF_GENERATION,
        )
        .is_err()
    );
}

// ── Node-proof generation cannot recur across placement eras (issue #3809) ───

#[test]
fn a_recurring_node_proof_generation_can_never_bind_a_proof() {
    // The concrete replay this refuses: an old settled host era wrote its proof
    // under a token derived from the release's observable shape, the cluster
    // then migrated host -> pod and back, and that same token names the NEW host
    // era. A same-boot node that missed the intervening cleanup/finalize rollout
    // would otherwise replay its stale proof into the new era.
    for recurring in [
        "host-netns-stable",
        "host-netns-finalize",
        "pod-netns-stable",
        // Era-shaped but not an era: no ordinal, a zero-padded ordinal, or a
        // bare prefix with nothing bound to it.
        "e.pod-to-host",
        "e0.pod-to-host",
        "e01.pod-to-host",
        "e3",
        "e3.",
        "era3.pod-to-host",
    ] {
        assert!(
            validate_node_proof_generation(recurring).is_err(),
            "{recurring} must not be accepted as a node-proof generation"
        );

        let registry = tempfile::tempdir().expect("registry");
        let node = identity(NODE_A, BOOT_1);
        write_node_attestation(
            registry.path(),
            ".udp-node-cleanup-proof-v1.json",
            &node,
            UdpPlacement::HostNetns,
            recurring,
        );
        let request = UdpPlacementRequest {
            node: Some(node.clone()),
            node_proof_generation: Some(recurring.to_string()),
            ..stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns)
        };
        let error = prepare_placement(registry.path(), &request)
            .err()
            .expect("a recurring node-proof generation must authorize nothing");
        assert!(error.contains("not era-qualified"), "{recurring}: {error}");
        assert!(
            !registry
                .path()
                .join(".udp-placement-state-v1.json")
                .exists(),
            "{recurring}: a refused release must write no ownership"
        );

        // The privileged preflight refuses to PUBLISH under one for the same
        // reason, so a repeatable token cannot enter the system from either end.
        assert!(
            ferrum_edge::proxy::udp_placement_migration::UdpMigrationContext::for_node_preflight(
                registry.path(),
                UdpPlacement::HostNetns,
                identity(NODE_A, BOOT_1),
                recurring,
            )
            .is_err(),
            "{recurring}: the preflight must refuse a recurring generation"
        );
    }

    // The era-qualified shape is what both ends accept.
    assert!(validate_node_proof_generation(PROOF_GENERATION).is_ok());
}

#[test]
fn a_proof_earned_in_an_earlier_placement_era_is_refused_by_the_next_one() {
    // host -> pod -> host, with the SAME operator-chosen migration generation
    // reused for both host transitions. Only the era ordinal distinguishes them,
    // which is exactly why it is the thing a proof is bound to.
    let registry = tempfile::tempdir().expect("registry");
    let node = identity(NODE_A, BOOT_1);
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &node,
        UdpPlacement::HostNetns,
        "e1.pod-to-host",
    );
    let later_era = UdpPlacementRequest {
        node: Some(node.clone()),
        node_proof_generation: Some("e5.pod-to-host".to_string()),
        ..stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns)
    };
    let error = prepare_placement(registry.path(), &later_era)
        .err()
        .expect("an earlier era's proof must not authorize a later one");
    assert!(
        error.contains("superseded node-proof generation"),
        "{error}"
    );
    assert!(
        !registry
            .path()
            .join(".udp-placement-state-v1.json")
            .exists(),
        "a refused rejoin must write no ownership"
    );

    // Re-proving the node in the CURRENT era is what admits it.
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &node,
        UdpPlacement::HostNetns,
        "e5.pod-to-host",
    );
    assert!(matches!(
        prepare_placement(registry.path(), &later_era),
        Ok(UdpPlacementDecision::RunStable)
    ));
}

// ── Authoritative node-UID provenance for the preflight (issue #3809) ───────

/// The exact on-disk shape the node-agent publishes, written directly so a test
/// can present a publication this process did not make.
fn published_identity(registry: &std::path::Path) -> Option<UdpNodeIdentity> {
    UdpNodeIdentity::resolve_published(registry, BOOT_1)
}

#[tokio::test]
async fn a_same_boot_node_object_recreation_cannot_hand_over_its_identity_or_proof() {
    // NODE_B's node-agent published its identity and its preflight published a
    // cleanup proof. The Node object is then deleted and recreated under the
    // same node NAME as NODE_A, on the SAME boot — so the surviving publication
    // records the CURRENT boot id and no reader can tell it from a live one.
    let registry = tempfile::tempdir().expect("registry");
    let predecessor = identity(NODE_B, BOOT_1);
    publish_node_identity_for(registry.path(), &predecessor).expect("predecessor publication");
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &predecessor,
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );
    assert_eq!(published_identity(registry.path()), Some(predecessor));

    // The preflight asks the API server instead, bound to this pod's node name.
    let resolved = resolve_authoritative_node_identity_with_boot_id(
        registry.path(),
        BOOT_1,
        None,
        Some("reused-node-name"),
        |node_name| async move {
            assert_eq!(node_name, "reused-node-name");
            Ok(NODE_A.to_string())
        },
    )
    .await
    .expect("the authoritative lookup resolves this node");
    assert_eq!(resolved, identity(NODE_A, BOOT_1));
    assert_eq!(
        published_identity(registry.path()),
        Some(identity(NODE_A, BOOT_1)),
        "the proven identity replaces the predecessor's publication"
    );

    // The predecessor's proof is not current for this node. The preflight
    // retracts leftover proof on every invocation rather than treating a
    // matching token as authority, and the steady-state guard refuses this
    // one outright.
    assert_eq!(
        node_cleanup_proof_is_current(
            registry.path(),
            UdpPlacement::HostNetns,
            &resolved,
            PROOF_GENERATION,
        ),
        Ok(false)
    );
    let error = prepare_placement(
        registry.path(),
        &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &resolved),
    )
    .err()
    .expect("node-name reuse must not inherit the predecessor's cleanup proof");
    assert!(error.contains("different Kubernetes node UID"), "{error}");

    // And the stale proof does not survive the run that refused it.
    retract_node_cleanup_proof(registry.path()).expect("stale proof retraction");
    assert!(
        !registry
            .path()
            .join(".udp-node-cleanup-proof-v1.json")
            .exists()
    );
}

#[tokio::test]
async fn the_preflight_resolves_its_identity_before_the_node_agent_has_published_one() {
    // The two DaemonSets have no startup ordering between them, so the preflight
    // routinely runs with NO published identity at all. It must still resolve
    // one rather than fail closed on the node-agent's schedule.
    let registry = tempfile::tempdir().expect("registry");
    assert_eq!(published_identity(registry.path()), None);

    let resolved = resolve_authoritative_node_identity_with_boot_id(
        registry.path(),
        BOOT_1,
        None,
        Some("fresh-node"),
        |_| async { Ok(NODE_A.to_string()) },
    )
    .await
    .expect("the preflight resolves its own identity");
    assert_eq!(resolved, identity(NODE_A, BOOT_1));
    assert_eq!(
        published_identity(registry.path()),
        Some(identity(NODE_A, BOOT_1))
    );

    // An explicit client-render value short-circuits the lookup entirely.
    let explicit = resolve_authoritative_node_identity_with_boot_id(
        registry.path(),
        BOOT_1,
        Some(NODE_B),
        Some("fresh-node"),
        |_| async { panic!("an explicit node UID must not consult Kubernetes") },
    )
    .await
    .expect("an explicit node UID resolves without a lookup");
    assert_eq!(explicit, identity(NODE_B, BOOT_1));
}

#[tokio::test]
async fn every_failed_lookup_or_publication_path_leaves_no_published_identity() {
    for (label, explicit, node_name, fetch_result) in [
        (
            "lookup failure",
            None,
            Some("some-node"),
            Err("the API server is unreachable".to_string()),
        ),
        (
            "node object without a UID",
            None,
            Some("some-node"),
            Ok(String::new()),
        ),
        (
            "hostile node UID",
            None,
            Some("some-node"),
            Ok("../../etc/passwd".to_string()),
        ),
        (
            "no node name and no explicit UID",
            None,
            None,
            Ok(String::new()),
        ),
    ] {
        let registry = tempfile::tempdir().expect("registry");
        // A publication from a PREVIOUS Kubernetes Node object is present, which
        // is precisely the state a failure must not leave behind.
        publish_node_identity_for(registry.path(), &identity(NODE_B, BOOT_1))
            .expect("predecessor publication");

        let error = resolve_authoritative_node_identity_with_boot_id(
            registry.path(),
            BOOT_1,
            explicit,
            node_name,
            |_| async move { fetch_result },
        )
        .await
        .err()
        .unwrap_or_else(|| panic!("{label} must fail closed"));
        assert!(!error.is_empty(), "{label}");
        assert_eq!(
            published_identity(registry.path()),
            None,
            "{label}: a failure must leave NO published identity, not a predecessor's"
        );
        assert!(
            !registry.path().join(".node-identity-v1.json").exists(),
            "{label}: the publication file itself must be gone"
        );
    }
}

#[tokio::test]
async fn an_unreadable_boot_id_retracts_stale_identity_before_failing() {
    // The public authoritative resolver must retract BEFORE it reads the boot
    // id. If `/proc` (or the override path) is unreadable, a predecessor
    // publication must not survive: that file records the CURRENT boot id even
    // when a PREVIOUS Kubernetes Node object wrote it.
    let registry = tempfile::tempdir().expect("registry");
    publish_node_identity_for(registry.path(), &identity(NODE_B, BOOT_1))
        .expect("predecessor publication");
    let identity_path = registry.path().join(".node-identity-v1.json");
    assert!(identity_path.exists(), "stale identity must be seeded");
    let identity_path_at_boot_id_read = identity_path.clone();

    let error = resolve_authoritative_node_identity_reading_boot_id(
        registry.path(),
        None,
        Some("some-node"),
        |_| async { panic!("boot-id failure must not consult Kubernetes") },
        move || {
            assert!(
                !identity_path_at_boot_id_read.exists(),
                "the boot id must be read only after the publication is retracted"
            );
            None
        },
    )
    .await
    .expect_err("an unreadable boot id must fail closed");
    assert!(error.contains("boot id"), "{error}");
    assert_eq!(
        published_identity(registry.path()),
        None,
        "an unreadable boot id must leave NO published identity"
    );
    assert!(
        !identity_path.exists(),
        "the publication file itself must be gone"
    );
}

#[test]
fn a_current_cleanup_proof_is_not_a_substitute_for_a_fresh_preflight_retirement() {
    // A leftover proof matching this node/era must not authorize a newly
    // starting preflight pod. Retract it: Helm rollback, a re-applied
    // historical manifest, or a restored ConfigMap can recreate the token a
    // monotonic counter cannot disprove. The CLI always retracts before the
    // idempotent cleanup republishes.
    let registry = tempfile::tempdir().expect("registry");
    let node = identity(NODE_A, BOOT_1);
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &node,
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );
    assert_eq!(
        node_cleanup_proof_is_current(
            registry.path(),
            UdpPlacement::HostNetns,
            &node,
            PROOF_GENERATION,
        ),
        Ok(true)
    );

    retract_node_cleanup_proof(registry.path()).expect("preflight retracts leftover proof");
    assert_eq!(
        node_cleanup_proof_is_current(
            registry.path(),
            UdpPlacement::HostNetns,
            &node,
            PROOF_GENERATION,
        ),
        Ok(false)
    );
    let error = prepare_placement(
        registry.path(),
        &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
    )
    .err()
    .expect("a retracted leftover proof cannot admit the host placement");
    assert!(
        error.contains("no node-specific cleanup attestation"),
        "{error}"
    );
}

#[test]
fn the_preflight_refuses_a_registry_publication_from_another_node() {
    // The registry-synchronization marker is the preflight's only evidence that
    // the pod inventory it is about to retire against is complete. One left by
    // the node-agent of a PREVIOUS Kubernetes Node object enumerates that
    // object's pods, so it must not satisfy this node's preflight.
    let registry = tempfile::tempdir().expect("registry");
    let preflight =
        ferrum_edge::proxy::udp_placement_migration::UdpMigrationContext::for_node_preflight(
            registry.path(),
            UdpPlacement::HostNetns,
            identity(NODE_A, BOOT_1),
            PROOF_GENERATION,
        )
        .expect("node preflight context");

    for stale in [None, Some(NODE_B)] {
        assert_eq!(
            publish_registry_sync_marker_for_pods(
                registry.path(),
                PROOF_GENERATION,
                &HashSet::new(),
                stale,
            ),
            Ok(true)
        );
        assert!(
            preflight.registry_sync_proof().is_none(),
            "a publication that does not name this node UID must not be consumable"
        );
    }

    assert_eq!(
        publish_registry_sync_marker_for_pods(
            registry.path(),
            PROOF_GENERATION,
            &HashSet::new(),
            Some(NODE_A),
        ),
        Ok(true)
    );
    assert!(
        preflight.registry_sync_proof().is_some(),
        "the current node-agent's publication must be consumable"
    );

    // The migration cleanup phase decides from durable node-bound ownership, so
    // it deliberately keeps consuming an unbound publication.
    let mesh = cleanup_context(
        registry.path(),
        &transition(
            UdpMigrationPhase::Cleanup,
            "mesh-cleanup",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
    );
    assert_eq!(
        publish_registry_sync_marker_for_pods(
            registry.path(),
            "mesh-cleanup",
            &HashSet::new(),
            None,
        ),
        Ok(true)
    );
    assert!(mesh.registry_sync_proof().is_some());
}

#[test]
fn finalize_refuses_to_leave_an_unbound_producer_owning_record() {
    // Cleanup/finalize is the documented recovery from unbound ownership, so it
    // must not be able to COMPLETE into the very shape it recovers from: a
    // record that runs a producer while naming no owning node UID. Finalize is
    // the boundary, because it is what flips `active` and returns `RunStable`.
    let registry = tempfile::tempdir().expect("registry");
    let cleanup = transition(
        UdpMigrationPhase::Cleanup,
        "unbound-finalize",
        UdpPlacement::PodNetns,
        UdpPlacement::HostNetns,
    );
    let context = cleanup_context(registry.path(), &cleanup);
    complete_cleanup(&context);

    let finalize = transition(
        UdpMigrationPhase::Finalize,
        "unbound-finalize",
        UdpPlacement::PodNetns,
        UdpPlacement::HostNetns,
    );
    let error = prepare_placement(registry.path(), &finalize)
        .err()
        .expect("finalize must refuse to bind nothing to a producer placement");
    assert!(
        error.contains("naming no owning Kubernetes node UID"),
        "{error}"
    );

    // Supplying the identity completes the same generation, and the record it
    // leaves behind is this node's own ownership.
    let node = identity(NODE_A, BOOT_1);
    assert!(matches!(
        prepare_placement(registry.path(), &on_node(finalize, &node)),
        Ok(UdpPlacementDecision::RunStable)
    ));
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_on_node(UdpPlacement::HostNetns, &node)
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));

    // `disabled` runs no producer and carries no traffic, so it stays
    // finalizable while the identity is unresolvable.
    let disabled_registry = tempfile::tempdir().expect("registry");
    let disable = transition(
        UdpMigrationPhase::Cleanup,
        "disable-unbound",
        UdpPlacement::PodNetns,
        UdpPlacement::Disabled,
    );
    let context = cleanup_context(disabled_registry.path(), &disable);
    complete_cleanup(&context);
    assert!(matches!(
        prepare_placement(
            disabled_registry.path(),
            &transition(
                UdpMigrationPhase::Finalize,
                "disable-unbound",
                UdpPlacement::PodNetns,
                UdpPlacement::Disabled,
            ),
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
}

struct HungHostReaper {
    script: String,
}

impl HostUdpCleanupReaper for HungHostReaper {
    fn reap_host_udp_state(
        &mut self,
        deadline: Option<std::time::Instant>,
    ) -> Result<(), OwnedShellError> {
        owned_shell::run_sh_c(&self.script, deadline)
    }
}

struct ImmediateHostReaper;

impl HostUdpCleanupReaper for ImmediateHostReaper {
    fn reap_host_udp_state(
        &mut self,
        deadline: Option<std::time::Instant>,
    ) -> Result<(), OwnedShellError> {
        if owned_shell::deadline_elapsed(deadline) {
            Err(OwnedShellError::DeadlineElapsed)
        } else {
            Ok(())
        }
    }
}

fn node_preflight_registry() -> (
    tempfile::TempDir,
    ferrum_edge::proxy::udp_placement_migration::UdpMigrationContext,
) {
    let registry = tempfile::tempdir().expect("registry");
    let node = identity(NODE_A, BOOT_1);
    assert_eq!(
        publish_registry_sync_marker_for_pods(
            registry.path(),
            PROOF_GENERATION,
            &HashSet::new(),
            Some(NODE_A),
        ),
        Ok(true)
    );
    let context =
        ferrum_edge::proxy::udp_placement_migration::UdpMigrationContext::for_node_preflight(
            registry.path(),
            UdpPlacement::HostNetns,
            node,
            PROOF_GENERATION,
        )
        .expect("node preflight context");
    (registry, context)
}

#[test]
fn preflight_deadline_kills_a_hung_host_reap_and_publishes_no_proof() {
    let (registry, context) = node_preflight_registry();
    let proof = registry.path().join(".udp-node-cleanup-proof-v1.json");
    let source = std::sync::Arc::new(DirectoryCaptureSource::new(registry.path()));
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime");
    let start = std::time::Instant::now();
    let outcome = runtime.block_on(run_udp_placement_cleanup_with_host_reaper(
        context,
        source,
        shutdown_rx,
        Some(tokio::time::Instant::now() + std::time::Duration::from_millis(250)),
        HungHostReaper {
            script: "sleep 30".to_string(),
        },
    ));
    let elapsed = start.elapsed();
    assert_eq!(outcome, UdpCleanupOutcome::DeadlineElapsed);
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "current-thread runtime must not block on the hung sleep, took {elapsed:?}"
    );
    assert!(
        !proof.exists(),
        "no cleanup attestation may be published after the deadline wins"
    );
}

#[test]
fn preflight_deadline_does_not_publish_when_it_has_already_elapsed() {
    let (registry, context) = node_preflight_registry();
    let proof = registry.path().join(".udp-node-cleanup-proof-v1.json");
    let source = std::sync::Arc::new(DirectoryCaptureSource::new(registry.path()));
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime");
    let outcome = runtime.block_on(run_udp_placement_cleanup_with_host_reaper(
        context,
        source,
        shutdown_rx,
        Some(
            tokio::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .expect("tokio instant"),
        ),
        ImmediateHostReaper,
    ));
    assert_eq!(outcome, UdpCleanupOutcome::DeadlineElapsed);
    assert!(
        !proof.exists(),
        "an already-elapsed deadline must not publish cleanup proof"
    );
}

#[test]
fn deadline_withhold_retracts_a_raced_cleanup_attestation() {
    let registry = tempfile::tempdir().expect("registry");
    let node = identity(NODE_A, BOOT_1);
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &node,
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );
    assert!(
        node_cleanup_proof_is_current(
            registry.path(),
            UdpPlacement::HostNetns,
            &node,
            PROOF_GENERATION,
        )
        .expect("readable proof")
    );

    withhold_node_cleanup_proof_after_deadline(registry.path()).expect("retract raced proof");
    assert!(
        !registry
            .path()
            .join(".udp-node-cleanup-proof-v1.json")
            .exists(),
        "a deadline result must not leave a usable cleanup attestation behind"
    );
    assert!(
        !node_cleanup_proof_is_current(
            registry.path(),
            UdpPlacement::HostNetns,
            &node,
            PROOF_GENERATION,
        )
        .expect("absent proof")
    );
}

#[test]
fn deadline_withhold_reports_retract_failure_and_leaves_no_usable_proof() {
    let registry = tempfile::tempdir().expect("registry");
    let node = identity(NODE_A, BOOT_1);
    let proof = registry.path().join(".udp-node-cleanup-proof-v1.json");
    write_node_attestation(
        registry.path(),
        ".udp-node-cleanup-proof-v1.json",
        &node,
        UdpPlacement::HostNetns,
        PROOF_GENERATION,
    );

    // A non-empty directory at the proof path cannot be unlinked by the
    // narrowly-scoped retract, and cannot be read as a version-1 attestation.
    std::fs::remove_file(&proof).expect("remove file");
    std::fs::create_dir(&proof).expect("directory occupying proof path");
    std::fs::write(proof.join("occupant"), b"keep-dir").expect("non-empty directory");

    let error = withhold_node_cleanup_proof_after_deadline(registry.path())
        .expect_err("retract of a directory publication must be reported");
    assert!(
        error.contains("retract") || error.contains("invalidate"),
        "{error}"
    );
    assert!(
        !node_cleanup_proof_is_current(
            registry.path(),
            UdpPlacement::HostNetns,
            &node,
            PROOF_GENERATION,
        )
        .unwrap_or(false),
        "a directory occupying the proof path must not authorize adoption"
    );
    let decision = prepare_placement(
        registry.path(),
        &stable_attested_on_node(UdpPlacement::HostNetns, UdpPlacement::HostNetns, &node),
    );
    assert!(
        !matches!(decision, Ok(UdpPlacementDecision::RunStable)),
        "deadline withhold must not leave a usable attestation"
    );
}
