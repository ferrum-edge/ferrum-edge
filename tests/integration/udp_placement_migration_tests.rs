use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use ferrum_edge::proxy::netns_capture::{
    DirectoryCaptureSource, PodCaptureSource, PodCaptureSourceIps, PodCaptureTarget,
};
use ferrum_edge::proxy::netns_udp_capture::{NetnsUdpCleanupBackend, NetnsUdpCleanupManager};
use ferrum_edge::proxy::udp_placement_migration::{
    UdpCleanupProofWindow, UdpMigrationFailureReason, UdpMigrationPhase, UdpPlacement,
    UdpPlacementDecision, UdpPlacementRequest, UdpRegistrySyncProof, clear_registry_sync_marker,
    prepare_placement, publish_registry_sync_marker_for_pods,
};

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
    }
}

fn stable_attested(target: UdpPlacement, established: UdpPlacement) -> UdpPlacementRequest {
    UdpPlacementRequest {
        established: Some(established),
        ..stable(target)
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
    assert_eq!(
        publish_registry_sync_marker_for_pods(
            context.registry_dir(),
            context.generation(),
            &HashSet::new(),
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
fn rebooted_or_new_node_adopts_the_release_attested_established_placement() {
    // A node that joined after the migration, or whose tmpfs registry directory
    // was recreated by a reboot, carries no durable record but provably no
    // predecessor rules either. Without adoption it would refuse host-netns
    // forever and never publish readiness.
    let registry = tempfile::tempdir().expect("registry");
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &stable_attested(UdpPlacement::HostNetns, UdpPlacement::HostNetns),
        ),
        Ok(UdpPlacementDecision::RunStable)
    ));
    assert!(
        ferrum_edge::proxy::udp_placement_migration::snapshot().established_adoption,
        "adoption must be visible to operators"
    );
    // The adoption is durable: a later restart resumes its own record and does
    // not depend on the attestation staying rendered.
    assert!(matches!(
        prepare_placement(registry.path(), &stable(UdpPlacement::HostNetns)),
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

    // Only a proven cleanup/finalize pair clears the quarantine.
    let cleanup = transition(
        UdpMigrationPhase::Cleanup,
        "repair-1",
        UdpPlacement::PodNetns,
        UdpPlacement::HostNetns,
    );
    let context = cleanup_context(registry.path(), &cleanup);
    complete_cleanup(&context);
    assert!(matches!(
        prepare_placement(
            registry.path(),
            &transition(
                UdpMigrationPhase::Finalize,
                "repair-1",
                UdpPlacement::PodNetns,
                UdpPlacement::HostNetns,
            ),
        ),
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
        prepare_placement(
            registry.path(),
            &transition(
                UdpMigrationPhase::Finalize,
                "repair-1",
                UdpPlacement::PodNetns,
                UdpPlacement::HostNetns,
            ),
        ),
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
    prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .expect("pod placement bootstrap");
    let cleanup = transition(
        UdpMigrationPhase::Cleanup,
        "rollout-42",
        UdpPlacement::PodNetns,
        UdpPlacement::HostNetns,
    );
    let first = cleanup_context(registry.path(), &cleanup);
    let resumed = cleanup_context(registry.path(), &cleanup);
    assert_eq!(first.generation(), resumed.generation());

    let finalize = transition(
        UdpMigrationPhase::Finalize,
        "rollout-42",
        UdpPlacement::PodNetns,
        UdpPlacement::HostNetns,
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
        prepare_placement(registry.path(), &stable(UdpPlacement::HostNetns)),
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
        publish_registry_sync_marker_for_pods(registry.path(), "temp-reap", &HashSet::new(),),
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
        publish_registry_sync_marker_for_pods(registry.path(), "temp-reap-safe", &HashSet::new(),),
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
    let bootstrap_cleanup = transition(
        UdpMigrationPhase::Cleanup,
        "host-bootstrap",
        UdpPlacement::PodNetns,
        UdpPlacement::HostNetns,
    );
    let context = cleanup_context(registry.path(), &bootstrap_cleanup);
    complete_cleanup(&context);
    prepare_placement(
        registry.path(),
        &transition(
            UdpMigrationPhase::Finalize,
            "host-bootstrap",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
    )
    .expect("host bootstrap finalize");

    let reverse = transition(
        UdpMigrationPhase::Cleanup,
        "reverse-7",
        UdpPlacement::HostNetns,
        UdpPlacement::PodNetns,
    );
    let context = cleanup_context(registry.path(), &reverse);
    assert!(prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns)).is_err());
    complete_cleanup(&context);
    prepare_placement(
        registry.path(),
        &transition(
            UdpMigrationPhase::Finalize,
            "reverse-7",
            UdpPlacement::HostNetns,
            UdpPlacement::PodNetns,
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
        if from == UdpPlacement::HostNetns {
            let bootstrap = cleanup_context(
                registry.path(),
                &transition(
                    UdpMigrationPhase::Cleanup,
                    "bootstrap-host",
                    UdpPlacement::PodNetns,
                    UdpPlacement::HostNetns,
                ),
            );
            complete_cleanup(&bootstrap);
            prepare_placement(
                registry.path(),
                &transition(
                    UdpMigrationPhase::Finalize,
                    "bootstrap-host",
                    UdpPlacement::PodNetns,
                    UdpPlacement::HostNetns,
                ),
            )
            .expect("bootstrap finalize");
        } else {
            prepare_placement(registry.path(), &stable(from)).expect("bootstrap placement");
        }
        assert!(prepare_placement(registry.path(), &stable(to)).is_err());
        let context = cleanup_context(
            registry.path(),
            &transition(UdpMigrationPhase::Cleanup, generation, from, to),
        );
        complete_cleanup(&context);
        prepare_placement(
            registry.path(),
            &transition(UdpMigrationPhase::Finalize, generation, from, to),
        )
        .expect("finalize transition");
        assert!(matches!(
            prepare_placement(registry.path(), &stable(to)),
            Ok(UdpPlacementDecision::RunStable)
        ));
    }
}

#[test]
fn interrupted_cleanup_rejects_stale_generation_and_predecessor() {
    let registry = tempfile::tempdir().expect("registry");
    prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .expect("bootstrap placement");
    cleanup_context(
        registry.path(),
        &transition(
            UdpMigrationPhase::Cleanup,
            "owned-generation",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
    );
    assert!(
        prepare_placement(
            registry.path(),
            &transition(
                UdpMigrationPhase::Cleanup,
                "stale-generation",
                UdpPlacement::PodNetns,
                UdpPlacement::HostNetns,
            ),
        )
        .is_err()
    );
    assert!(
        prepare_placement(
            registry.path(),
            &transition(
                UdpMigrationPhase::Finalize,
                "owned-generation",
                UdpPlacement::HostNetns,
                UdpPlacement::PodNetns,
            ),
        )
        .is_err()
    );
}

#[test]
fn completed_generation_cannot_authorize_a_later_cleanup_transition() {
    let registry = tempfile::tempdir().expect("registry");
    prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .expect("bootstrap placement");
    let first = transition(
        UdpMigrationPhase::Cleanup,
        "generation-once",
        UdpPlacement::PodNetns,
        UdpPlacement::HostNetns,
    );
    complete_cleanup(&cleanup_context(registry.path(), &first));
    prepare_placement(
        registry.path(),
        &transition(
            UdpMigrationPhase::Finalize,
            "generation-once",
            UdpPlacement::PodNetns,
            UdpPlacement::HostNetns,
        ),
    )
    .expect("first finalize");

    let error = prepare_placement(
        registry.path(),
        &transition(
            UdpMigrationPhase::Cleanup,
            "generation-once",
            UdpPlacement::HostNetns,
            UdpPlacement::PodNetns,
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
        publish_registry_sync_marker_for_pods(registry.path(), "generation-b", &HashSet::new(),),
        Ok(true)
    );
    assert!(context.registry_sync_proof().is_none());
    assert_eq!(
        publish_registry_sync_marker_for_pods(registry.path(), "generation-a", &HashSet::new(),),
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
    prepare_placement(registry.path(), &stable(UdpPlacement::PodNetns))
        .expect("bootstrap placement");
    let cleanup = transition(
        UdpMigrationPhase::Cleanup,
        "generation-a",
        UdpPlacement::PodNetns,
        UdpPlacement::HostNetns,
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

    let finalize = transition(
        UdpMigrationPhase::Finalize,
        "generation-a",
        UdpPlacement::PodNetns,
        UdpPlacement::HostNetns,
    );
    assert!(prepare_placement(registry.path(), &finalize).is_err());
}

#[test]
fn registry_relist_ack_requires_every_expected_pod_entry() {
    let registry = tempfile::tempdir().expect("registry");
    let expected = HashSet::from(["pod-a".to_string(), "pod-b".to_string()]);
    std::fs::write(registry.path().join("pod-a"), b"/cg/1\n").expect("first pod entry");
    assert_eq!(
        publish_registry_sync_marker_for_pods(registry.path(), "generation-a", &expected),
        Ok(false)
    );
    assert!(!registry.path().join(".udp-registry-synced").exists());

    std::fs::write(registry.path().join("pod-b"), b"/cg/2\n").expect("second pod entry");
    assert_eq!(
        publish_registry_sync_marker_for_pods(registry.path(), "generation-a", &expected),
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
    assert!(source.list_targets_for_migration().is_err());
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
