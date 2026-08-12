//! Static Helm/chart contract coverage for Ambient UDP established-placement
//! attestation (issue #3703 / PR #3795).
//!
//! These tests pin the settled-vs-migrating attestation gates without mutating
//! `.github/workflows/ci.yml` (Trusted Cross Build Policy forbids Cross-surface
//! workflow edits outside the protected ARM64 job). Hosted CI still exercises
//! `helm template` for the broader UDP placement upgrade matrix.

use std::path::PathBuf;

fn chart_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("charts/ferrum-mesh")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(chart_root().join(rel)).unwrap_or_else(|e| {
        panic!("failed to read charts/ferrum-mesh/{rel}: {e}");
    })
}

#[test]
fn values_document_installed_contract_attestation() {
    let values = read("values.yaml");
    assert!(
        values.contains("FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED")
            && values.contains("ferrum-mesh-udp-placement-<release>")
            && values.contains("never rendered by the release that changes the placement"),
        "ambient values must document release-level established attestation from the installed ConfigMap"
    );
}

#[test]
fn ambient_attests_only_settled_upgrade_matching_installed_contract() {
    let ambient = read("templates/ambient-daemonset.yaml");

    // Settled host (or pod) placement: derive attestation only for Ambient +
    // stable phase + upgrade, and only when the installed ConfigMap already
    // recorded this exact target in a settled (stable/finalize) phase.
    assert!(
        ambient.contains(
            "eq $ambientTopology \"ambient\") (eq $ambientUdpMigrationPhase \"stable\") .Release.IsUpgrade"
        ),
        "established attestation must require Ambient topology, current stable phase, and an upgrade"
    );
    assert!(
        ambient.contains("ferrum-mesh-udp-placement-%s")
            && ambient
                .contains("lookup \"v1\" \"ConfigMap\" .Release.Namespace $ambientUdpContractName"),
        "attestation must read the installed placement ConfigMap, never invent cluster state"
    );
    assert!(
        ambient.contains(
            "eq (toString (index $ambientUdpInstalledData \"target\")) $ambientUdpTarget"
        ) && ambient.contains(
            "has (toString (index $ambientUdpInstalledData \"phase\")) (list \"stable\" \"finalize\")"
        ),
        "installed contract must already record the same target in a settled phase"
    );
    assert!(
        ambient.contains("$ambientUdpEstablished = $ambientUdpTarget")
            && ambient.contains("ternary \"host-netns\" \"pod-netns\" $ambientUdpHostNetns"),
        "a settled host placement must be able to attest host-netns (and pod-netns when that is the target)"
    );
}

#[test]
fn ambient_never_attests_while_current_release_is_migrating() {
    let ambient = read("templates/ambient-daemonset.yaml");

    // Attestation derivation is gated on the CURRENT release phase being
    // stable. A cleanup/finalize rollout that is CHANGING placement therefore
    // cannot emit FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED for itself.
    let established_gate = "eq $ambientTopology \"ambient\") (eq $ambientUdpMigrationPhase \"stable\") .Release.IsUpgrade";
    assert!(
        ambient.contains(established_gate),
        "migrating releases (cleanup/finalize) must be excluded from established attestation"
    );
    assert!(
        !ambient.contains("eq $ambientUdpMigrationPhase \"cleanup\") .Release.IsUpgrade")
            && !ambient.contains("eq $ambientUdpMigrationPhase \"finalize\") .Release.IsUpgrade"),
        "established attestation must not be derivable during cleanup or finalize of the current release"
    );

    // Rendering of the env entry is gated on the derived value, not on migration
    // phase alone, so an empty $ambientUdpEstablished yields no env row.
    assert!(
        ambient.contains(
            "if and $ambientUdpEstablished (not (hasKey $ambientEnv \"FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED\"))"
        ),
        "chart must render FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED only when established is derived"
    );
    assert!(
        ambient.contains("- name: FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED")
            && ambient.contains("value: {{ $ambientUdpEstablished | quote }}"),
        "settled attestation env row must quote the derived established placement"
    );
}

#[test]
fn ambient_env_override_still_wins_over_chart_managed_attestation() {
    let ambient = read("templates/ambient-daemonset.yaml");
    assert!(
        ambient
            .contains("not (hasKey $ambientEnv \"FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED\")"),
        "explicit ambient.env attestation must win so GitOps/client-render pipelines can supply their own gate"
    );
}
