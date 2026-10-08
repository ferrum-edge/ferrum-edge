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

fn read_repo(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("failed to read {rel}: {e}");
    })
}

/// Collapse Markdown line wraps so prose substring checks stay semantic, not
/// sensitive to ordinary reflow whitespace.
fn normalize_markdown_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The four regions of the single ambient DaemonSet that the privilege boundary
/// is stated in: pod-level fields, the preflight init container, the
/// steady-state proxy container, and the volume list.
struct AmbientRegions {
    pod_spec: (usize, usize),
    init: (usize, usize),
    proxy: (usize, usize),
    volumes: (usize, usize),
}

fn ambient_regions(ambient: &str) -> AmbientRegions {
    let pod_spec_start = ambient
        .find("      serviceAccountName: ferrum-mesh")
        .expect("ambient pod spec");
    let preflight_gate = ambient
        .find("      {{- if $ambientUdpRunNodePreflight }}")
        .expect("preflight render gate");
    let init_start = ambient
        .find("      initContainers:")
        .expect("preflight must be an init container in the ambient pod");
    let proxy_start = ambient
        .find("\n      containers:")
        .expect("steady-state container list");
    let volumes_gate = ambient
        .find("\n      volumes:")
        .expect("ambient volume list");
    assert!(
        pod_spec_start < preflight_gate
            && preflight_gate < init_start
            && init_start < proxy_start
            && proxy_start < volumes_gate,
        "the preflight init container must be rendered between the pod fields and the \
         steady-state container: Kubernetes only orders init-before-container WITHIN one pod"
    );
    AmbientRegions {
        pod_spec: (pod_spec_start, preflight_gate),
        init: (init_start, proxy_start),
        proxy: (proxy_start, volumes_gate),
        volumes: (volumes_gate, ambient.len()),
    }
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

// ── Node-specific proof boundary (issue #3809) ──────────────────────────────

/// The preflight must stay an init container in the PROXY'S OWN POD.
///
/// That is the ordering fence the whole node-proof boundary rests on. Kubernetes
/// runs an init container to completion before the app container starts within
/// one pod, and orders nothing at all between two DaemonSets. Both
/// `.node-identity-v1.json` and `.udp-node-cleanup-proof-v1.json` live on the
/// shared registry hostPath and survive a Node object deleted and recreated
/// under the same name on the same boot, so a preflight in its own workload
/// could be scheduled AFTER a replacement proxy had already accepted that stale
/// old-UID pair. Eventual retraction does not undo an adoption that already
/// happened.
#[test]
fn the_privileged_node_preflight_runs_before_the_proxy_in_the_same_pod() {
    let ambient = read("templates/ambient-daemonset.yaml");

    assert!(
        ambient.contains(
            "$ambientUdpRunNodePreflight := and $ambientUdpLifecycle $ambientUdpHostNetns (eq $ambientUdpMigrationPhase \"stable\") $ambientUdpNodePreflightEnabled"
        ),
        "the preflight must render only for a settled host-netns Ambient placement"
    );

    assert_eq!(
        ambient.matches("kind: DaemonSet").count(),
        1,
        "the ambient template must render exactly ONE DaemonSet: a second workload for the \
         preflight has no Kubernetes startup ordering against the proxy it must precede"
    );
    for forbidden in [
        "ferrum-mesh-udp-node-preflight",
        "ferrum-udp-node-preflight-holder",
        "/bin/sleep",
        "restartPolicy:",
    ] {
        assert!(
            !ambient.contains(forbidden),
            "a separate preflight workload (and its inert privileged-pod holder) must not \
             come back: found {forbidden}"
        );
    }

    let regions = ambient_regions(&ambient);
    let init = &ambient[regions.init.0..regions.init.1];

    assert!(
        init.contains("- name: ferrum-udp-node-preflight")
            && init.contains(
                "args: [\"ambient-udp-preflight\", \"--host-proc-root\", {{ $ambientUdpHostProcMountPath | quote }}, \"-v\"]"
            ),
        "the ambient pod's init container must run the node preflight against the explicit \
         host procfs root"
    );
    assert!(
        !init.contains("restartPolicy"),
        "the init container must not be a native sidecar: a container-level \
         restartPolicy: Always would keep the privileged process alive beside the proxy"
    );
    assert!(
        init.contains("{{- end }}"),
        "the preflight init container must close its own render gate before the \
         steady-state container list"
    );
}

/// Settled host-netns renders NO `hostPID`. The preflight replaces it with a
/// read-only host `/proc` mount that only the init container receives, because
/// `hostPID` is a PodSpec field and would follow the long-running proxy.
#[test]
fn the_settled_host_placement_renders_no_host_pid_for_the_preflight() {
    let ambient = read("templates/ambient-daemonset.yaml");
    let regions = ambient_regions(&ambient);
    let pod_spec = &ambient[regions.pod_spec.0..regions.pod_spec.1];

    assert_eq!(
        ambient.matches("hostPID: true").count(),
        1,
        "hostPID must be rendered in exactly one place, and only for setns capture"
    );
    assert!(
        pod_spec.contains("{{- if $ambientSetnsCapture }}")
            && pod_spec.contains("hostPID: true")
            && !pod_spec.contains("$ambientUdpRunNodePreflight"),
        "hostPID must be gated on the steady-state producer's own setns capture mode, \
         never on the preflight"
    );
    assert!(
        !ambient.contains("or $ambientSetnsCapture $ambientUdpRunNodePreflight")
            && !ambient.contains("or $ambientUdpRunNodePreflight $ambientSetnsCapture"),
        "the preflight must never widen the pod-scoped hostPID gate again"
    );
}

/// The host-proc mount and all four elevated capabilities are declared on the
/// init container only, so they are gone before the proxy process exists.
#[test]
fn the_preflight_host_proc_mount_and_capabilities_are_init_only() {
    let ambient = read("templates/ambient-daemonset.yaml");
    let regions = ambient_regions(&ambient);
    let init = &ambient[regions.init.0..regions.init.1];
    let proxy = &ambient[regions.proxy.0..regions.proxy.1];
    let volumes = &ambient[regions.volumes.0..regions.volumes.1];

    assert!(
        ambient.contains("{{- $ambientUdpHostProcMountPath := \"/host/proc\" -}}"),
        "the mount path and the --host-proc-root argument must come from ONE chart value, \
         or a mismatch would silently send target-pid reads back at the container's own /proc"
    );
    assert!(
        init.contains("- name: preflight-host-proc")
            && init.contains("mountPath: {{ $ambientUdpHostProcMountPath }}")
            && init.contains("readOnly: true"),
        "the preflight init container must mount the host procfs read-only"
    );
    assert!(
        volumes.contains("{{- if $ambientUdpRunNodePreflight }}")
            && volumes.contains("- name: preflight-host-proc")
            && volumes.contains("path: /proc"),
        "the host procfs volume must render only when the preflight runs"
    );
    assert_eq!(
        ambient.matches("preflight-host-proc").count(),
        2,
        "the host procfs must appear exactly twice: one init-container mount and one volume"
    );
    assert!(
        !proxy.contains("preflight-host-proc") && !proxy.contains("host/proc"),
        "the steady-state container must never receive the host procfs mount"
    );

    assert!(
        init.contains("allowPrivilegeEscalation: false")
            && init.contains("drop:\n                - ALL"),
        "the init container must declare its complete privilege surface"
    );
    assert_eq!(
        init.matches("add:").count(),
        1,
        "the init container must declare exactly one capability add list"
    );
    let added = &init[init.find("add:").expect("capability add list")..];
    for privilege in ["NET_ADMIN", "NET_RAW", "SYS_ADMIN", "SYS_PTRACE"] {
        let entry = format!("\n                - {privilege}\n");
        assert_eq!(
            added.matches(&entry).count(),
            1,
            "the preflight needs exactly one {privilege} entry"
        );
    }
    assert_eq!(
        added.matches("\n                - ").count(),
        4,
        "the init container's capability list must be exactly NET_ADMIN, NET_RAW, SYS_ADMIN, SYS_PTRACE"
    );
    assert!(
        init.contains("name: node-waypoint-pod-registry") && init.contains("name: cgroup"),
        "the preflight must still mount the pod registry and host cgroup"
    );
}

/// The steady-state proxy container carries no part of the preflight.
#[test]
fn the_steady_state_proxy_container_carries_no_preflight_surface() {
    let ambient = read("templates/ambient-daemonset.yaml");
    let regions = ambient_regions(&ambient);
    let proxy = &ambient[regions.proxy.0..regions.proxy.1];

    assert!(
        proxy.contains("- name: ferrum-edge") && proxy.contains("args: [\"run\"]"),
        "the ambient pod's only ordinary container is the proxy"
    );
    for forbidden in [
        "$ambientUdpRunNodePreflight",
        "ambient-udp-preflight",
        "host-proc",
        "initContainers",
    ] {
        assert!(
            !proxy.contains(forbidden),
            "the steady-state proxy container must not carry {forbidden}"
        );
    }
    assert!(
        proxy.contains(
            "allowPrivilegeEscalation: {{ $ambientSc.allowPrivilegeEscalation | default false }}"
        ),
        "the steady-state proxy must emit Restricted allowPrivilegeEscalation, defaulting to false"
    );

    // SYS_ADMIN/SYS_PTRACE still exist for the setns capture modes whose RUNNING
    // producer enters pod netns; they must never be reachable through the
    // preflight gate.
    let setns_gate = proxy
        .find("{{- if $ambientSetnsCapture")
        .expect("steady-state setns capability gate");
    for privilege in ["SYS_ADMIN", "SYS_PTRACE"] {
        assert_eq!(
            proxy.matches(privilege).count(),
            1,
            "{privilege} must appear exactly once in the steady-state container"
        );
        let at = proxy.find(privilege).expect("privilege position");
        assert!(
            setns_gate < at,
            "{privilege} must sit inside the setns-capture gate, not the preflight one"
        );
    }

    // Datapath capability names must stay unquoted (`- BPF`, not `- "BPF"`):
    // NodeWaypoint eBPF live and Helm Chart greps match the unquoted form on
    // both the proxy and the node-agent.
    assert!(
        proxy.contains("- {{ $cap }}")
            && !proxy.contains("$cap | quote")
            && !proxy.contains("ambientDropNormalized 0 | quote"),
        "steady-state capability names must render unquoted so topology greps keep matching"
    );
    let bpf_gate = proxy
        .find("{{- if $nodeWaypointRegistryEnabled -}}")
        .expect("NodeWaypoint BPF/PERFMON gate");
    for cap in ["BPF", "PERFMON"] {
        assert_eq!(
            proxy.matches(&format!("\"{cap}\"")).count(),
            1,
            "{cap} must appear once as a required NodeWaypoint capability token"
        );
        let at = proxy.find(&format!("\"{cap}\"")).expect("cap position");
        assert!(
            bpf_gate < at && at < setns_gate,
            "{cap} must sit inside the NodeWaypoint registry gate"
        );
    }
}

#[test]
fn ambient_proxy_security_context_defaults_allow_privilege_escalation_false() {
    let ambient = read("templates/ambient-daemonset.yaml");
    let values = read("values.yaml");
    let schema = read("values.schema.json");

    assert!(
        !ambient.contains(
            "ambient.securityContext.allowPrivilegeEscalation is not a steady-state proxy field"
        ),
        "allowPrivilegeEscalation is a Restricted proxy field, not a preflight-only key"
    );
    assert!(
        ambient.contains(
            "allowPrivilegeEscalation: {{ $ambientSc.allowPrivilegeEscalation | default false }}"
        ),
        "the proxy must render allowPrivilegeEscalation with a false default"
    );

    let ambient_sc = schema
        .split("\"ambientSecurityContext\"")
        .nth(1)
        .expect("ambientSecurityContext schema");
    let ambient_sc = ambient_sc
        .split("\"workloadResources\"")
        .next()
        .unwrap_or(ambient_sc);
    assert!(
        ambient_sc.contains("allowPrivilegeEscalation")
            && ambient_sc.contains("readOnlyRootFilesystem")
            && ambient_sc.contains("capabilities"),
        "ambient.securityContext must admit allowPrivilegeEscalation, readOnlyRootFilesystem, and capabilities"
    );

    let marker = "Unlike the Deployment workloads this is NOT rendered verbatim";
    assert!(
        values.contains(marker),
        "values must document that ambient.securityContext is assembled field by field"
    );
    let sc_at = values
        .find(marker)
        .expect("ambient securityContext comment");
    let sc_window = &values[sc_at..sc_at.saturating_add(1600).min(values.len())];
    assert!(
        sc_window.contains("allowPrivilegeEscalation: false"),
        "ambient values must default allowPrivilegeEscalation to false for Restricted"
    );
    assert!(
        !sc_window.contains("Privilege-escalation is NOT a proxy key")
            && !sc_window.contains("not a steady-state proxy field"),
        "values must not claim privilege-escalation belongs only to the preflight init container"
    );
    assert!(
        sc_window.contains("readOnlyRootFilesystem: true") && sc_window.contains("- ALL"),
        "ambient values must keep read-only root and drop ALL"
    );
}

#[test]
fn the_node_proof_generation_is_derived_from_the_installed_contract_for_both_daemonsets() {
    let helpers = read("templates/_helpers.tpl");
    let ambient = read("templates/ambient-daemonset.yaml");
    let node_agent = read("templates/node-agent-daemonset.yaml");

    assert!(
        helpers.contains("define \"ferrum-mesh.ambientUdpNodeProofGeneration\"")
            && helpers.contains("lookup \"v1\" \"ConfigMap\" .Release.Namespace $contractName"),
        "the node-proof generation must be derived from the INSTALLED placement contract"
    );
    // The helper reads the PERSISTED era-qualified token and nothing else. A
    // token derived from the release's observable shape repeats the moment a
    // target and phase recur, which is exactly the replay issue #3809 refuses.
    assert!(
        helpers.contains("index $data \"nodeProofGeneration\""),
        "the node-proof generation must come from the contract's persisted \
         era-qualified field"
    );
    assert!(
        helpers.contains("fail-closes a PRESENT era/generation")
            && helpers.contains("pre-contract absence of BOTH fields"),
        "the helper must stay aligned with the contract's fail-closed pair boundary"
    );
    assert!(
        !helpers.contains("printf \"%s-%s\" $target $phase"),
        "a `<target>-<phase>` fallback recurs across placement eras and must not exist"
    );

    // One shared helper, so the ambient pod, its preflight, and the node-agent's
    // registry-synchronization publication can never disagree.
    for (name, template) in [("ambient", &ambient), ("node-agent", &node_agent)] {
        assert!(
            template.contains("include \"ferrum-mesh.ambientUdpNodeProofGeneration\""),
            "{name} must derive the node-proof generation from the shared helper"
        );
        assert!(
            template.contains("- name: FERRUM_MESH_CAPTURE_UDP_NODE_PROOF_GENERATION"),
            "{name} must carry FERRUM_MESH_CAPTURE_UDP_NODE_PROOF_GENERATION"
        );
    }
    assert!(
        node_agent.contains(
            "\"FERRUM_MESH_CAPTURE_UDP_NODE_PROOF_GENERATION\"\n  \"FERRUM_K8S_NODE_UID\"\n  \"FERRUM_MESH_CAPTURE_UDP_NODE_BOOT_ID_PATH\"\n  \"FERRUM_MESH_TOPOLOGY\""
        ),
        "the node-agent must treat the node-proof generation, explicit node UID, \
         and boot-id path as chart-managed"
    );

    // Fail closed rather than rendering a preflight that can prove nothing.
    assert!(
        ambient.contains(
            "requires an installed placement contract to derive FERRUM_MESH_CAPTURE_UDP_NODE_PROOF_GENERATION"
        ),
        "a settled host placement with no derivable proof generation must fail rendering"
    );
}

#[test]
fn client_render_parity_keeps_an_explicit_env_value_under_the_same_boundary() {
    let ambient = read("templates/ambient-daemonset.yaml");
    let values = read("values.yaml");

    // An explicit ambient.env value still wins for BOTH variables, so a
    // GitOps/client-render pipeline supplies its own — and is held to the same
    // node-specific proof contract, because the boundary lives in the runtime.
    for name in [
        "FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED",
        "FERRUM_MESH_CAPTURE_UDP_NODE_PROOF_GENERATION",
    ] {
        assert!(
            ambient.contains(&format!("not (hasKey $ambientEnv \"{name}\")")),
            "an explicit ambient.env {name} must win over the chart-derived value"
        );
    }
    assert!(
        ambient.contains("authorizes nothing on its own")
            || ambient.contains("DESIRED STATE, not authorization"),
        "the template must record that the release attestation is not authorization"
    );

    // The escape hatch is documented as non-relaxing.
    assert!(
        values.contains("udpNodePreflight")
            && values.contains("does NOT relax the runtime boundary"),
        "values must document that disabling the preflight keeps the runtime fail-closed"
    );
    assert!(
        values.contains("runs as an INIT CONTAINER in the ambient")
            && values.contains("orders nothing between two DaemonSets")
            && values.contains("--host-proc-root /host/proc")
            && values.contains("no host PID"),
        "values must document the same-pod ordering fence and the host-proc mount that \
         replaces pod-scoped hostPID"
    );
}

/// The operator-facing lifecycle prose must describe the shipped shape: a
/// same-pod init container, a host-proc mount instead of hostPID, and WHY a
/// separate workload would reopen the stale same-boot proof window.
#[test]
fn the_operator_docs_describe_the_same_pod_preflight_lifecycle() {
    let mesh = read_repo("docs/mesh.md");
    let node_agent_security = read_repo("docs/node_agent_security.md");
    let configuration = read_repo("docs/configuration.md");
    let cli = read_repo("docs/cli.md");
    let schema = read("values.schema.json");

    for (name, doc) in [
        ("docs/mesh.md", &mesh),
        ("docs/node_agent_security.md", &node_agent_security),
        ("docs/configuration.md", &configuration),
    ] {
        assert!(
            !doc.contains("ferrum-mesh-udp-node-preflight")
                && !doc.contains("dedicated preflight DaemonSet")
                && !doc.contains("inert unprivileged holder"),
            "{name} must not describe a separate preflight DaemonSet or its holder"
        );
    }

    assert!(
        mesh.contains("init container** on")
            && mesh.contains("Why it lives in the proxy's own pod")
            && mesh.contains("name on the same boot**")
            && mesh.contains("Do not split this into a separate DaemonSet."),
        "docs/mesh.md must state the same-pod ordering fence and the stale same-boot pair \
         it exists to refuse"
    );
    assert!(
        mesh.contains("Why it needs no `hostPID`")
            && mesh.contains("--host-proc-root /host/proc")
            && mesh.contains("translated into the reading process's PID")
            && mesh.contains("`/proc/self/ns/net` — the stage's own namespace"),
        "docs/mesh.md must explain the host-proc redirect, including why cgroup.procs \
         cannot be used through a foreign procfs and what stays on the own procfs"
    );
    assert!(
        node_agent_security.contains("read-only host\n`/proc` mount**")
            && node_agent_security.contains("no `hostPID`")
            && node_agent_security.contains("A separate DaemonSet has no such ordering"),
        "docs/node_agent_security.md must record the init-only host-proc mount and the \
         ordering the separate-workload shape would forfeit"
    );
    assert!(
        cli.contains("--host-proc-root <PATH>") && cli.contains("fails closed"),
        "docs/cli.md must document the flag and its fail-closed validation"
    );
    assert!(
        schema.contains("read-only host /proc mount instead of pod-scoped hostPID")
            && !schema.contains("dedicated DaemonSet"),
        "values.schema.json must describe the shipped preflight shape"
    );
    let mesh_normalized = normalize_markdown_whitespace(&mesh);
    assert!(
        mesh.contains("automountServiceAccountToken: false")
            && mesh.contains("kube-api-access")
            && mesh_normalized.contains("only when no explicit `FERRUM_K8S_NODE_UID`")
            && node_agent_security.contains("automountServiceAccountToken: false")
            && node_agent_security.contains("does not receive the projected token"),
        "operator docs must record ServiceAccount token isolation for the privileged init"
    );
}

#[test]
fn the_node_agent_can_read_its_own_node_object_for_the_uid_binding() {
    let rbac = read("templates/node-agent-rbac.yaml");
    assert!(
        rbac.contains("and $naAmbientUdpLifecycle (not $naHasExplicitNodeUid) (not .Values.nodeAgent.ingressRedirectIfaces)")
            && rbac.contains("$naHasExplicitNodeUid := hasKey $naAmbientEnv \"FERRUM_K8S_NODE_UID\""),
        "the node-agent identity GET must render only when Ambient UDP needs the API \
         and an explicit UID is absent"
    );
    assert!(
        rbac.contains("resources: [\"nodes\"]") && rbac.contains("verbs: [\"get\"]"),
        "the node-agent needs a read-only nodes grant to resolve Node.metadata.uid"
    );
    assert!(
        !rbac.contains("verbs: [\"*\"]")
            && !rbac.contains("\"create\"")
            && !rbac.contains("\"patch\""),
        "the nodes grant must stay read-only"
    );
}

/// The placement contract carries the migration-era provenance the whole proof
/// boundary rests on, and the era is what makes the token non-recurring.
#[test]
fn the_placement_contract_persists_a_non_recurring_node_proof_era() {
    let contract = read("templates/udp-placement-contract.yaml");

    assert!(
        contract.contains("{{- if $nodeProofGeneration }}")
            && !contract.contains("{{- if $nodeProofGeneration -}}")
            && contract.contains("nodeProofEra: {{ $nodeProofEra | toString | quote }}")
            && contract.contains("nodeProofGeneration: {{ $nodeProofGeneration | quote }}"),
        "a stamped era-qualified token must emit both node-proof keys on their own \
         YAML lines; a right-chomp on the generation gate concatenates nodeProofEra \
         onto the preceding comment"
    );
    // Starting a migration opens a NEW era; resuming the same cleanup release
    // keeps the one already open, so retries are idempotent while transitions
    // strictly advance.
    assert!(
        contract.contains("{{- $nextEra := add1 $previousEra -}}")
            && contract.contains("{{- $nodeProofEra = $nextEra -}}")
            && contract
                .contains("{{- $nodeProofGeneration = printf \"e%d.%s\" $nodeProofEra $generation")
            && contract.contains("{{- if not (and $resumeCleanup $nodeProofGeneration) -}}"),
        "a cleanup START must open the next era and an era-qualified token"
    );
    // Finalize and every settled release after it carry the era forward
    // unchanged: only the cleanup branch reassigns it.
    assert!(
        contract.matches("$nodeProofEra = ").count() == 1
            && contract.matches("$nodeProofGeneration = ").count() == 1,
        "only the cleanup branch may stamp a new era; every other phase carries \
         the installed contract's value forward"
    );
    assert!(
        contract.contains("hasKey $previous \"nodeProofEra\"")
            && contract.contains("hasKey $previous \"nodeProofGeneration\"")
            && contract.contains("{{- $hasPreviousEra = true -}}")
            && contract.contains("{{- $hasPreviousGeneration = true -}}"),
        "the carried-forward token must track installed map-key presence, not rendered value truthiness"
    );
    assert!(
        contract.contains(
            "$previousNodeProofGeneration = trim (toString (index $previous \"nodeProofGeneration\"))"
        ),
        "the carried-forward token must come from the installed contract"
    );
}

/// A present installed era/generation pair is one authority boundary. Coercing
/// a malformed era to zero, or carrying a generation that does not name that
/// era, would let the next cleanup emit `e1.*` again.
#[test]
fn the_placement_contract_fails_closed_on_a_present_malformed_or_inconsistent_era_pair() {
    let contract = read("templates/udp-placement-contract.yaml");

    // Validation runs only when at least one key is present. Absence of BOTH
    // keys is the pre-contract cleanup entry that may stamp era 1.
    assert!(
        contract.contains("{{- if or $hasPreviousEra $hasPreviousGeneration -}}"),
        "pair validation must run only when an installed era or generation key is present"
    );
    assert!(
        contract.contains("{{- if or (not $hasPreviousEra) (not $hasPreviousGeneration) -}}"),
        "a partial key pair must fail before validating present values"
    );
    assert!(
        contract.contains(
            "fail \"installed Ambient UDP nodeProofEra/nodeProofGeneration pair is incomplete"
        ),
        "a partial key pair must fail rendering rather than filling the missing half"
    );
    assert!(
        contract.contains(
            "fail \"installed Ambient UDP nodeProofEra is malformed or out of supported bounds"
        ),
        "a malformed or out-of-range installed era must fail rendering"
    );
    assert!(
        contract.contains(
            "fail \"installed Ambient UDP nodeProofGeneration is malformed or out of supported bounds"
        ),
        "a generation token outside the supported charset/length must fail rendering"
    );
    assert!(
        contract.contains(
            "fail \"installed Ambient UDP nodeProofGeneration is not the era-qualified e<era>.<generation> token bound to the installed nodeProofEra"
        ),
        "a generation whose era does not equal nodeProofEra must fail rendering"
    );
    assert!(
        contract.contains("{{- $generationPrefix := printf \"e%s.\" $rawEra -}}")
            && contract.contains("hasPrefix $generationPrefix $previousNodeProofGeneration")
            && contract.contains("(eq $previousNodeProofGeneration $generationPrefix)"),
        "the installed generation must be the exact e<era>.<nonempty generation> shape \
         whose era equals nodeProofEra"
    );

    let era_fail = contract
        .find("installed Ambient UDP nodeProofEra is malformed or out of supported bounds")
        .expect("malformed-era fail");
    let atoi = contract
        .find("$previousEra = atoi $rawEra")
        .expect("atoi of the installed era");
    assert!(
        era_fail < atoi,
        "atoi must not run on an unvalidated installed era"
    );
    assert!(
        !contract.contains(
            "{{- if regexMatch \"^[1-9][0-9]{0,9}$\" $rawEra -}}{{- $previousEra = atoi $rawEra -}}{{- end -}}"
        ),
        "a malformed installed era must not be silently treated as zero"
    );

    // Overflow/re-entry is refused BEFORE the ordinal is assigned.
    assert!(
        contract.contains(
            "fail \"Ambient UDP nodeProofEra cannot increment without overflowing the supported 1..=10 digit ordinal"
        ) && contract.contains("{{- $nextEraStr := $nextEra | toString -}}")
            && contract.contains("regexMatch \"^[1-9][0-9]{0,9}$\" $nextEraStr"),
        "increment must fail closed when the next ordinal would leave the 1..=10 digit bound"
    );
    let overflow = contract
        .find("cannot increment without overflowing")
        .expect("overflow fail");
    let assign = contract
        .find("$nodeProofEra = $nextEra")
        .expect("era assignment after increment");
    assert!(
        overflow < assign,
        "overflow must be refused before the next era is stamped"
    );

    // Pre-contract cleanup still stamps era 1 from a zero predecessor, and a
    // cleanup retry with a present generation keeps the era already open.
    assert!(
        contract.contains("{{- $previousEra := 0 -}}")
            && contract.contains("{{- $nextEra := add1 $previousEra -}}"),
        "pre-contract absence of both fields must still be able to stamp era 1"
    );
    assert!(
        contract.contains("{{- if not (and $resumeCleanup $nodeProofGeneration) -}}"),
        "re-rendering the same cleanup release must keep the era already open"
    );
    assert!(
        contract.matches("add1 $previousEra").count() == 1,
        "successive cleanup starts must strictly increase the ordinal; only one \
         increment site may exist"
    );
}

/// Initial stable pod-netns/disabled installs must not stamp era zero or an empty
/// generation; that present-but-unstamped pair would strand the first cleanup on
/// the next upgrade.
#[test]
fn the_placement_contract_omits_node_proof_keys_until_cleanup_stamps_era_one() {
    let contract = read("templates/udp-placement-contract.yaml");

    assert!(
        contract.contains("{{- if $nodeProofGeneration }}")
            && !contract.contains("{{- if $nodeProofGeneration -}}")
            && contract.contains("nodeProofEra: {{ $nodeProofEra | toString | quote }}")
            && contract.contains("nodeProofGeneration: {{ $nodeProofGeneration | quote }}"),
        "both node-proof keys must be emitted only once a non-empty era-qualified \
         generation exists, and the gate must not right-chomp onto the preceding comment"
    );
    assert!(
        contract.contains("both must be absent so cleanup can stamp era 1"),
        "the installed-pair validator must still treat both-absent as the pre-contract \
         cleanup entry"
    );
    let gate = contract
        .find("{{- if $nodeProofGeneration }}")
        .expect("node-proof generation gate");
    let era_line = contract
        .find("nodeProofEra: {{ $nodeProofEra | toString | quote }}")
        .expect("nodeProofEra emission");
    let generation_line = contract
        .find("nodeProofGeneration: {{ $nodeProofGeneration | quote }}")
        .expect("nodeProofGeneration emission");
    let end_gate = contract[gate..]
        .find("{{- end }}")
        .map(|offset| gate + offset)
        .expect("node-proof generation gate end");
    assert!(
        gate < era_line && era_line < generation_line && generation_line < end_gate,
        "both node-proof keys must render on their own lines inside the non-empty generation gate"
    );
    assert!(
        !contract.contains("{{- if $nodeProofGeneration -}}"),
        "a right-chomp on the generation gate concatenates nodeProofEra onto the \
         preceding YAML comment, leaving only nodeProofGeneration as a real data key"
    );
    assert!(
        contract.contains("{{- $previousEra := 0 -}}")
            && contract.contains("{{- $nextEra := add1 $previousEra -}}"),
        "pre-contract absence must still let the first cleanup stamp era 1"
    );
}

/// Helm treats explicit numeric zero and empty values as empty when coerced
/// through `default`, so presence must be tracked with `hasKey`.
#[test]
fn the_placement_contract_rejects_present_but_empty_or_zero_era_pair_keys() {
    let contract = read("templates/udp-placement-contract.yaml");

    assert!(
        !contract.contains("default \"\" (index $previous \"nodeProofEra\")")
            && !contract.contains("default \"\" (index $previous \"nodeProofGeneration\")"),
        "installed era/generation presence must not rely on default-empty coercion"
    );
    assert!(
        contract.contains("{{- $rawEra = trim (toString (index $previous \"nodeProofEra\")) -}}")
            && contract.contains(
                "$previousNodeProofGeneration = trim (toString (index $previous \"nodeProofGeneration\"))"
            ),
        "present keys must still be validated even when their rendered values are empty or zero"
    );
    assert!(
        contract.contains("{{- if or (not $hasPreviousEra) (not $hasPreviousGeneration) -}}"),
        "only one present key must fail closed before the pre-contract era-1 path"
    );
    assert!(
        contract.contains("{{- if or $hasPreviousEra $hasPreviousGeneration -}}")
            && contract.contains("regexMatch \"^[1-9][0-9]{0,9}$\" $rawEra"),
        "both keys present with explicit zero or empty values must still hit malformed-era validation"
    );
}

/// The preflight resolves this node's UID itself, so it can never pair a stale
/// identity publication with the stale cleanup proof written under it.
#[test]
fn the_preflight_binds_its_node_lookup_to_this_pods_node_name() {
    let ambient = read("templates/ambient-daemonset.yaml");
    let rbac = read("templates/ambient-rbac.yaml");
    let nodes_rbac = rbac
        .split("\n---\n")
        .find(|document| document.contains("resources: [\"nodes\"]"))
        .expect("ambient-rbac.yaml must contain the nodes ClusterRole document");

    assert!(
        ambient.contains(
            "if and $ambientUdpRunNodePreflight (hasKey $ambientEnv \"FERRUM_K8S_NODE_NAME\")"
        ) && ambient.contains(
            "ambient.env.FERRUM_K8S_NODE_NAME is chart-managed when the settled host-netns UDP preflight is enabled"
        ),
        "a literal ambient.env.FERRUM_K8S_NODE_NAME must fail rendering when the preflight is enabled"
    );
    assert!(
        !ambient.contains("if not (hasKey $ambientEnv \"FERRUM_K8S_NODE_NAME\")"),
        "the preflight must not gate the downward-API fieldRef on ambient.env presence"
    );

    let regions = ambient_regions(&ambient);
    let init_block = &ambient[regions.init.0..regions.init.1];
    assert!(
        init_block.contains("if not $hasExplicitNodeUid")
            && init_block.contains("- name: FERRUM_K8S_NODE_NAME")
            && init_block.contains("fieldPath: spec.nodeName"),
        "the preflight must receive this pod's node name from the downward API when no explicit UID is set"
    );
    assert_eq!(
        init_block.matches("- name: FERRUM_K8S_NODE_NAME").count(),
        1,
        "the preflight container must render exactly one FERRUM_K8S_NODE_NAME env row"
    );
    assert_eq!(
        init_block.matches("fieldPath: spec.nodeName").count(),
        1,
        "the preflight init container must bind FERRUM_K8S_NODE_NAME to spec.nodeName exactly once"
    );
    assert!(
        !init_block.contains("index $ambientEnv \"FERRUM_K8S_NODE_NAME\""),
        "the preflight must not source FERRUM_K8S_NODE_NAME from ambient.env"
    );

    assert!(
        rbac.contains("$ambientUdpRunNodePreflight := and $ambientUdpLifecycle $ambientUdpHostNetns (eq $ambientUdpMigrationPhase \"stable\") $ambientUdpNodePreflightEnabled")
            && rbac.contains("$hasExplicitNodeUid := hasKey $ambientEnv \"FERRUM_K8S_NODE_UID\"")
            && rbac.contains("if and $ambientUdpRunNodePreflight (not $hasExplicitNodeUid)"),
        "the ambient nodes:get grant must render only when the settled host-netns \
         preflight will run and an explicit UID is absent"
    );

    assert!(
        nodes_rbac.contains("resources: [\"nodes\"]")
            && nodes_rbac.contains("verbs: [\"get\"]"),
        "the ambient service account needs a read-only nodes grant for the preflight lookup"
    );
    // Least privilege: get without list/watch/write. Kubernetes RBAC does not
    // treat a get without resourceNames as a single-object restriction; the
    // runtime request is bound to spec.nodeName.
    for forbidden in [
        "\"list\"",
        "\"watch\"",
        "\"create\"",
        "\"update\"",
        "\"patch\"",
        "\"delete\"",
        "\"*\"",
    ] {
        assert!(
            !nodes_rbac.contains(forbidden),
            "the ambient nodes grant must not carry {forbidden}"
        );
    }
    assert!(
        !nodes_rbac.contains("resourceNames:"),
        "do not add resourceNames: a static name cannot name this pod's node, \
         and claiming a single-object restriction Kubernetes does not provide \
         is worse than documenting the runtime binding"
    );
    assert!(
        nodes_rbac.contains(
            "name: ferrum-mesh-ambient\n    namespace: {{ .Release.Namespace }}",
        ),
        "the grant must bind the ambient DaemonSet's own service account"
    );
    assert!(
        nodes_rbac.contains("`get` without `resourceNames` as a single-object restriction")
            && nodes_rbac.contains("runtime request is what binds the lookup"),
        "the Role comment must not claim an enforcement boundary Kubernetes RBAC \
         does not provide"
    );
}

/// An explicit UID skips the Node API lookup, but a stray node-name override
/// must still fail closed when the preflight is enabled.
#[test]
fn the_preflight_explicit_node_uid_skips_the_name_fieldref_but_rejects_name_override() {
    let ambient = read("templates/ambient-daemonset.yaml");
    let values = read("values.yaml");

    assert!(
        ambient.contains("$hasExplicitNodeUid := hasKey $ambientEnv \"FERRUM_K8S_NODE_UID\"")
            && ambient.contains("if not $hasExplicitNodeUid"),
        "the preflight must omit the downward-API node name when an explicit UID is supplied"
    );
    assert!(
        ambient.contains(
            "if and $ambientUdpRunNodePreflight (hasKey $ambientEnv \"FERRUM_K8S_NODE_NAME\")"
        ),
        "an explicit UID must not relax the chart-owned node-name binding"
    );
    assert!(
        values.contains("ambient.env.FERRUM_K8S_NODE_NAME") && values.contains("fails rendering"),
        "values must document that ambient.env.FERRUM_K8S_NODE_NAME is rejected when the preflight is enabled"
    );
}

/// Automatic kubelet token projection would hand the privileged init container
/// a bearer token even when an explicit UID means it never calls the API.
/// Pod-level automount is off; a short-lived projected volume is mounted into
/// the proxy always and into the init container only on the lookup path.
#[test]
fn the_ambient_pod_isolates_the_service_account_token_from_the_explicit_uid_init() {
    let ambient = read("templates/ambient-daemonset.yaml");
    let values = read("values.yaml");
    let regions = ambient_regions(&ambient);
    let pod_spec = &ambient[regions.pod_spec.0..regions.pod_spec.1];
    let init = &ambient[regions.init.0..regions.init.1];
    let proxy = &ambient[regions.proxy.0..regions.proxy.1];
    let volumes = &ambient[regions.volumes.0..regions.volumes.1];

    assert!(
        pod_spec.contains("automountServiceAccountToken: false"),
        "the ambient pod must disable kubelet automatic token projection"
    );
    assert!(
        !pod_spec.contains("automountServiceAccountToken: true"),
        "automatic token projection must not be re-enabled on the ambient pod"
    );

    assert!(
        volumes.contains("- name: kube-api-access")
            && volumes.contains("projected:")
            && volumes.contains("serviceAccountToken:")
            && volumes.contains("expirationSeconds: 3607")
            && volumes.contains("path: token")
            && volumes.contains("name: kube-root-ca.crt")
            && volumes.contains("path: ca.crt")
            && volumes.contains("fieldPath: metadata.namespace")
            && volumes.contains("path: namespace"),
        "kube-api-access must be a short-lived projected volume with token, CA, and namespace"
    );
    assert!(
        !volumes.contains("{{- if or $ambientInNetnsCapture")
            && !volumes.contains("{{- if or $ambientInNetnsCapture $ambientSpireEnabled $ambientUdpRunNodePreflight }}"),
        "the kube-api-access volume must render even when no cgroup/SPIRE/preflight volumes do"
    );

    let proxy_mount = "- name: kube-api-access\n              mountPath: /var/run/secrets/kubernetes.io/serviceaccount\n              readOnly: true";
    assert!(
        proxy.contains(proxy_mount),
        "the steady-state proxy must always mount the projected token read-only at the standard in-cluster path"
    );
    assert!(
        !proxy.contains("if not $hasExplicitNodeUid") && !proxy.contains("if $hasExplicitNodeUid"),
        "the proxy mount must not be gated on whether the preflight needs a Node GET"
    );

    assert!(
        init.contains("if not $hasExplicitNodeUid")
            && init.contains("- name: kube-api-access")
            && init.contains("mountPath: /var/run/secrets/kubernetes.io/serviceaccount")
            && init.contains("readOnly: true"),
        "the preflight may mount the projected token only when it must perform the Node GET"
    );
    let init_token_gate = init
        .rfind("{{- if not $hasExplicitNodeUid }}")
        .expect("init token mount gate");
    let init_token = &init[init_token_gate..];
    assert!(
        init_token.contains("- name: kube-api-access") && init_token.contains("{{- end }}"),
        "the init-container token mount must sit inside the explicit-UID-absent gate"
    );
    assert_eq!(
        init.matches("- name: kube-api-access").count(),
        1,
        "the init container must declare the token mount in exactly one place"
    );

    assert!(
        values.contains("automountServiceAccountToken: false")
            && values.contains("kube-api-access")
            && values.contains("withholds the projected ServiceAccount token"),
        "values must document token isolation on the explicit-UID path"
    );
}

/// The relay pod identity is chart-managed downward API and nothing else
/// (issues #3956, #3957).
///
/// `FERRUM_MESH_NODE_WAYPOINT_RELAY_POD_UID` selects which cgroup the node-agent
/// authorizes as the UDP relay SENDER, so an operator-supplied value would be a
/// way to hand the sender proof to an arbitrary pod — the one thing the proof
/// exists to prevent. It must come from `metadata.uid`, and an `ambient.env`
/// override (with or without an external-secret suffix) must fail the render.
#[test]
fn the_node_waypoint_relay_pod_uid_is_downward_api_only() {
    let ambient = read("templates/ambient-daemonset.yaml");

    let regions = ambient_regions(&ambient);
    let steady_state = &ambient[regions.proxy.0..regions.proxy.1];

    assert!(
        steady_state.contains("- name: FERRUM_MESH_NODE_WAYPOINT_RELAY_POD_UID")
            && steady_state.contains("fieldPath: metadata.uid"),
        "the NodeWaypoint proxy must receive its own pod UID from the downward API"
    );
    assert_eq!(
        steady_state
            .matches("- name: FERRUM_MESH_NODE_WAYPOINT_RELAY_POD_UID")
            .count(),
        1,
        "the relay identity must be declared exactly once in the proxy container"
    );
    assert!(
        ambient.contains(
            "ambient.env.FERRUM_MESH_NODE_WAYPOINT_RELAY_POD_UID is chart-managed for NodeWaypoint"
        ),
        "an operator-supplied relay identity must fail the render, not silently win"
    );
    assert!(
        ambient.contains("FERRUM_MESH_NODE_WAYPOINT_RELAY_POD_UID%s")
            && ambient.contains(
                r#"{{- range $suffix := list "" "_FILE" "_VAULT" "_AWS" "_AZURE" "_GCP" -}}"#
            ),
        "the override guard must cover the external-secret suffixes too"
    );
}

/// SPIRE and the preflight bind the downward-API node name in DIFFERENT
/// containers of the same pod, so neither duplicates an env row inside one
/// container's env list.
#[test]
fn spire_and_preflight_each_bind_node_name_in_their_own_container() {
    let ambient = read("templates/ambient-daemonset.yaml");

    let regions = ambient_regions(&ambient);
    let init_block = &ambient[regions.init.0..regions.init.1];
    let steady_state = &ambient[regions.proxy.0..regions.proxy.1];

    assert_eq!(
        init_block.matches("- name: FERRUM_K8S_NODE_NAME").count(),
        1,
        "the preflight container must carry exactly one FERRUM_K8S_NODE_NAME row"
    );
    assert!(
        steady_state.contains(
            "if or $nodeWaypointRegistryEnabled (and $ambientSpireEnabled $ambientSpireUsesNodeName)"
        ) && steady_state.contains("- name: FERRUM_K8S_NODE_NAME")
            && steady_state.contains("fieldPath: spec.nodeName"),
        "SPIRE and NodeWaypoint registry profiles must still receive their own downward-API node name in the steady-state container"
    );
    assert!(
        ambient.contains(
            "ambient.env.%s is chart-managed when ambient.spire.enabled=true; set ambient.spire values instead"
        ),
        "SPIRE must keep FERRUM_K8S_NODE_NAME chart-managed separately from the preflight binding"
    );
}

#[test]
fn the_node_agent_receives_the_explicit_uid_and_boot_id_path_from_ambient_env() {
    let node_agent = read("templates/node-agent-daemonset.yaml");
    let rbac = read("templates/node-agent-rbac.yaml");

    assert!(
        node_agent.contains("hasKey $ambientEnv \"FERRUM_K8S_NODE_UID\"")
            && node_agent.contains("- name: FERRUM_K8S_NODE_UID")
            && node_agent.contains("index $ambientEnv \"FERRUM_K8S_NODE_UID\""),
        "the node-agent must receive ambient.env FERRUM_K8S_NODE_UID so it publishes \
         the same UID-bound registry proof the preflight requires"
    );
    assert!(
        node_agent.contains("hasKey $ambientEnv \"FERRUM_MESH_CAPTURE_UDP_NODE_BOOT_ID_PATH\"")
            && node_agent.contains("- name: FERRUM_MESH_CAPTURE_UDP_NODE_BOOT_ID_PATH")
            && node_agent
                .contains("index $ambientEnv \"FERRUM_MESH_CAPTURE_UDP_NODE_BOOT_ID_PATH\""),
        "the node-agent must receive ambient.env FERRUM_MESH_CAPTURE_UDP_NODE_BOOT_ID_PATH \
         so it stamps .node-identity-v1.json under the same incarnation the preflight reads"
    );
    assert!(
        node_agent.contains("\"FERRUM_K8S_NODE_UID\"")
            && node_agent.contains("\"FERRUM_MESH_CAPTURE_UDP_NODE_BOOT_ID_PATH\"")
            && node_agent.contains(
                "fail (printf \"nodeAgent.env.%s is chart-managed; set the corresponding nodeAgent value instead of overriding the rendered environment\" $name)"
            ),
        "conflicting nodeAgent.env overrides of the explicit UID or boot-id path must fail rendering"
    );
    assert!(
        rbac.contains("verbs: [\"get\", \"list\", \"watch\"]"),
        "ingress-topology monitoring must keep its independently required broader read verbs"
    );
}
