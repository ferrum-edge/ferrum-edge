//! Static contracts for the Ambient host-network UDP live-kernel gate (#3705).
//!
//! These pin workflow triggers, required-mode behavior, fixture invariants,
//! bounded diagnostics, and Ferrum-owned cleanup without executing the live
//! fixture.

use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|error| {
        panic!("failed to read {rel}: {error}");
    })
}

#[test]
fn ambient_host_udp_live_workflow_requires_live_mode_and_exact_counts() {
    let workflow = read(".github/workflows/ambient-host-udp-live.yml");
    assert!(
        workflow.contains("FERRUM_LIVE_TESTS_REQUIRED: \"1\""),
        "hosted gate must set required live mode"
    );
    assert!(
        workflow.contains("tests/k8s/ambient_host_udp_live/run.sh"),
        "workflow must invoke the shared fixture runner"
    );
    assert!(
        !workflow.contains("draft: true"),
        "workflow must not be draft-gated"
    );
}

/// The workflow must run unconditionally and decide relevance from an
/// immutable trusted-base classifier, never from a top-level `paths:` filter
/// the pull request itself supplies. A `paths:` filter would let a pull request
/// make the required check disappear entirely instead of reporting a verdict.
#[test]
fn ambient_host_udp_live_workflow_is_unconditional_with_a_trusted_base_relevance_gate() {
    let workflow = read(".github/workflows/ambient-host-udp-live.yml");

    assert!(
        !workflow.contains("    paths:") && !workflow.contains("    paths-ignore:"),
        "the live workflow must carry no top-level event path filter; relevance \
         belongs to the trusted-base classifier job"
    );
    assert!(
        workflow.contains("  pull_request:\n") && workflow.contains("  merge_group:\n"),
        "the live workflow must trigger on every pull request and merge-group run"
    );

    // Relevance is computed from the base branch's copy of the classifier,
    // read by object id, never from the pull request's own checkout.
    assert!(
        workflow.contains("git cat-file blob \"$entry_object\" > \"$trusted_filter\""),
        "relevance must read the trusted filter by pinned object id"
    );
    assert!(
        workflow.contains("python3 -I \"$trusted_filter\" --self-test"),
        "the trusted filter must self-test under an isolated interpreter"
    );
    assert!(
        !workflow.contains("python3 .github/scripts/live_suite_path_filter.py"),
        "relevance must never execute the pull request's own classifier"
    );
    assert!(
        workflow.contains("github.event.merge_group.base_sha")
            && workflow.contains("merge_group base_sha missing or malformed"),
        "merge-group runs must bind relevance to the event's base SHA"
    );

    // The introducing bootstrap is gone now that main knows the suite. The
    // permanent path must execute the trusted classifier directly and must not
    // retain an stderr-shaped exception that could force relevance on failure.
    assert!(
        workflow.contains("plan=\"$(python3 -I \"$trusted_filter\" \"${filter_args[@]}\")\""),
        "the permanent relevance path must execute the immutable trusted-base classifier"
    );
    assert!(
        !workflow.contains("invalid choice: 'ambient-host-udp'")
            && !workflow.contains("filter_err="),
        "the one-time unknown-suite bootstrap must be fully removed"
    );

    assert!(
        workflow.contains("    name: Ambient Host UDP Live\n"),
        "the final gate must be named exactly `Ambient Host UDP Live`"
    );
    assert!(
        workflow.contains("    if: always()"),
        "the final gate must run on every event, including skipped live runs"
    );
    assert!(
        workflow.contains("if: needs.changes.outputs.relevant == 'true'"),
        "the live job must be bound to the trusted relevance verdict"
    );
    assert!(
        workflow.contains("${{ needs.ambient-host-udp-live.result }}\" != \"success\""),
        "the gate must fail when a relevant live job fails or is absent"
    );

    // The separately trusted verifier freezes both the relevance block above
    // and its binding to the live job. This pull request intentionally makes
    // its own base-loaded policy check red, but once merged no later pull
    // request can rewrite the gate to self-declare irrelevance.
    let cross_policy = read(".github/scripts/verify_cross_build_policy.py");
    assert!(
        cross_policy.contains(
            "\"ambient-host-udp-live.yml\": (\n        \"changes\",\n        \
             \"ambient-host-udp-live\",\n        \"Ambient host-UDP trigger\",\n        \
             \"ambient-host-udp\",\n        \"ambient-host-udp\",\n    ),"
        ),
        "the trusted cross-policy verifier must freeze the Ambient host-UDP relevance contract"
    );
}

/// The required-CI verifier must pin the workflow's unconditional event
/// ownership and exact final context. The separately trusted cross-build
/// verifier deliberately cannot be changed by this pull request.
#[test]
fn ambient_host_udp_live_gate_is_owned_by_the_required_ci_verifier() {
    let required_ci = read(".github/scripts/verify_required_ci.py");
    assert!(
        required_ci
            .contains("\".github/workflows/ambient-host-udp-live.yml\": \"Ambient Host UDP Live\""),
        "the required-CI verifier must require an unconditional merge-group \
         owner for `Ambient Host UDP Live`"
    );
    assert!(
        required_ci.contains("REQUIRED_MERGE_GROUP_WORKFLOWS"),
        "the workflow must be checked through the unconditional required-owner contract"
    );
}

#[test]
fn ambient_host_udp_live_runner_fail_closed_and_bounded_diagnostics() {
    let runner = read("tests/k8s/ambient_host_udp_live/run.sh");
    assert!(
        runner.contains("FERRUM_LIVE_TESTS_REQUIRED"),
        "runner must honor required live mode"
    );
    assert!(
        runner.contains("fail_required"),
        "runner must convert skips into hard failures when required"
    );
    assert!(runner.contains("redact"), "diagnostics must be redacted");
    assert!(
        runner.contains("lines >= 200") && runner.contains("length(rendered) > 16384"),
        "diagnostics must be bounded"
    );
    assert!(
        runner.contains("mktemp \"${TMPDIR:-/tmp}/ferrum-host-udp-lib.XXXXXX\"")
            && runner.contains("mktemp \"${TMPDIR:-/tmp}/ferrum-host-udp-functional.XXXXXX\""),
        "unredacted test output must never be placed in the uploaded artifact tree"
    );
    assert!(
        runner.contains("FERRUM_MESH_UDP_HOST"),
        "cleanup must target Ferrum-owned host UDP chains"
    );
    assert!(
        runner.contains("lookup 33135") || runner.contains("table 33135"),
        "cleanup must target the Ferrum-owned host UDP routing table"
    );
    assert!(
        runner.contains("priority 101"),
        "cleanup must target the Ferrum-owned host UDP rule priority"
    );
    assert!(
        !runner.contains("lookup 33133"),
        "cleanup must not touch the pod-netns table"
    );
    assert!(
        !runner.contains("flush table"),
        "cleanup must never flush a routing table"
    );
    assert!(
        runner.contains("proxy::host_udp_capture_live_tests"),
        "runner must execute the lib live-kernel module"
    );
    assert!(
        runner.contains("functional_mesh_live_host_udp_capture"),
        "runner must execute the production ProxyHostUdpBackend functional live test"
    );
    assert!(
        runner.contains("expected exactly 2 ambient host-UDP lib live tests"),
        "runner must pin the lib live pass count"
    );
    assert!(
        runner.contains("expected exactly 1 ambient host-UDP functional live test"),
        "runner must pin the functional live pass count"
    );
}

/// #3804: the disposable outer netns is the ordinary ownership boundary.
/// Ordinary teardown must not delete canonical host objects; isolation is
/// proven structurally; early SKIP paths stay network-inert; the privileged
/// lock is rooted safely; and lock FD open never uses eval.
#[test]
fn ambient_host_udp_live_runner_uses_disposable_outer_netns_ownership_boundary() {
    let runner = read("tests/k8s/ambient_host_udp_live/run.sh");
    let readme = read("tests/k8s/ambient_host_udp_live/README.md");

    // Early SKIP / preflight before lock or outer-netns creation.
    let early_main = runner
        .find("# Temp cleanup only until the exclusive lock is held")
        .expect("main-path early temp cleanup marker must exist");
    let preflight = runner
        .find("SKIP: throwaway netns / mangle preflight failed")
        .expect("mangle preflight SKIP must remain");
    let lock_gate = runner
        .find("# --- From here on: exclusive lock, then disposable outer netns")
        .expect("post-preflight lock gate marker must exist");
    let outer = runner
        .find("unshare --mount --net --propagation private")
        .expect("ordinary root execution must create a disposable outer netns");
    assert!(
        early_main < preflight && preflight < lock_gate && lock_gate < outer,
        "preflight, then lock, then outer netns creation must stay ordered"
    );
    assert!(
        runner.contains("trap early_temp_cleanup EXIT")
            && runner.contains("SKIP: not root")
            && runner.contains("SKIP: $bin unavailable")
            && runner.contains("SKIP: throwaway netns / mangle preflight failed"),
        "early SKIP paths must remain available before mutation"
    );
    assert!(
        !runner.contains("trap cleanup_trap EXIT"),
        "the old unconditional cleanup_trap must not remain"
    );

    // Structural isolation proof — never trust an env flag alone.
    assert!(
        runner.contains("prove_disposable_outer_netns")
            && runner.contains("/proc/1/ns/net")
            && runner.contains("still in the init/host network namespace")
            && runner.contains("still in the parent network namespace"),
        "outer-netns isolation must be proven via self vs parent/init identities"
    );
    assert!(
        runner.contains("mount_and_prove_disposable_sysfs")
            && runner.contains("mount -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys")
            && runner.contains("ip link add \"$probe_host\" type veth peer name \"$probe_peer\"")
            && runner.contains("disposable sysfs view does not track the owned network namespace")
            && runner.contains("disposable sysfs view retained a removed namespace probe"),
        "the private mount namespace must expose a freshly mounted sysfs tied to the owned netns"
    );
    assert!(
        runner.contains("Do not trust FERRUM_HOST_UDP_LIVE_IN_OUTER_NETNS")
            || runner.contains("never trusted as proof"),
        "forgeable IN_OUTER_NETNS env flags must not be the isolation proof"
    );
    assert!(
        !runner.contains("IN_OUTER_NETNS=\"${FERRUM_HOST_UDP_LIVE_IN_OUTER_NETNS"),
        "runner must not gate ownership on a forgeable IN_OUTER_NETNS env value"
    );

    // Fixed shared-filesystem lock before outer netns; safe dynamic FD, no eval.
    assert!(
        runner.contains("flock -n")
            && runner.contains("/run/ferrum-edge-ambient-host-udp-live.lock")
            && runner
                .contains("another ambient_host_udp_live owner already holds the exclusive lock"),
        "a second fixture invocation must fail before mutation via the fixed exclusive lock"
    );
    assert!(
        runner.contains("exec {LOCK_FD}>\"$FERRUM_HOST_UDP_LIVE_LOCK_PATH\"")
            && runner.contains("exec {LOCK_FD}>&-")
            && !runner.contains("eval \"exec"),
        "lock FD open/close must use safe Bash dynamic-FD redirection without eval"
    );
    assert!(
        runner.contains("ignoring FERRUM_HOST_UDP_LIVE_LOCK_DIR")
            && runner.contains("lock path is fixed"),
        "configurable lock directories must not be accepted as hostile-input surface"
    );
    assert!(
        runner.contains("stat -Lc '%u:%a'")
            && runner.contains("root-owned and not group/world-writable")
            && runner.contains("must be a regular file, never a symlink")
            && runner.contains("must be root-owned and mode 0600")
            && runner.contains("umask 077")
            && !runner.contains("/tmp/ferrum-host-udp-live-locks"),
        "the root-opened lock must not be redirectable through attacker-owned /tmp state"
    );

    // Ordinary teardown never deletes canonical networking objects.
    assert!(
        runner.contains("ordinary_exit_cleanup")
            && runner.contains("must NEVER enumerate or delete"),
        "ordinary cleanup must document the no-host-object-deletion contract"
    );
    assert!(
        !runner.contains("ownership_safe_cleanup")
            && !runner.contains("remove_owned_object")
            && !runner.contains("write_ownership_ledger")
            && !runner.contains("list_canonical_host_udp_objects"),
        "per-object ledger deletion is not the ordinary ownership model"
    );
    let ordinary = runner
        .find("ordinary_exit_cleanup()")
        .expect("ordinary_exit_cleanup definition");
    let emergency = runner
        .find("emergency_destroy_canonical()")
        .expect("emergency_destroy_canonical definition");
    let ordinary_body = &runner[ordinary..emergency];
    assert!(
        !ordinary_body.contains("iptables -t mangle -D")
            && !ordinary_body.contains("ip6tables -t mangle -D")
            && !ordinary_body.contains("ip rule del")
            && !ordinary_body.contains("ip route del"),
        "ordinary_exit_cleanup must not delete iptables/rules/routes"
    );

    // Handled signals terminate and reap the complete owned child process
    // group before ordinary (non-destructive) cleanup releases the lock.
    assert!(
        runner.contains("setsid unshare --mount --net --propagation private")
            && runner.contains("OUTER_PID=$!")
            && runner.contains("kill -TERM -- \"-$outer_pid\"")
            && runner.contains("kill -KILL -- \"-$outer_pid\"")
            && runner.contains("wait \"$outer_pid\"")
            && runner.contains("trap 'handle_outer_signal 130' INT")
            && runner.contains("trap 'handle_outer_signal 143' TERM")
            && runner.contains("trap 'handle_outer_signal 129' HUP"),
        "INT/TERM/HUP must terminate and reap the child tree before lock release"
    );
    assert!(
        runner.contains("trap 'early_temp_cleanup; exit 130' INT")
            && runner.contains("trap 'early_temp_cleanup; exit 143' TERM")
            && runner.contains("trap 'early_temp_cleanup; exit 129' HUP"),
        "inner fixture signals must stay temp-only"
    );

    // Emergency destroy is explicit, loud, and never the ordinary exit path.
    assert!(
        runner.contains("FERRUM_HOST_UDP_LIVE_EMERGENCY_DESTROY_CANONICAL")
            && runner.contains("emergency_destroy_canonical")
            && runner.contains("this path is never reached from ordinary fixture exits"),
        "emergency canonical destroy must be an explicit opt-in path"
    );
    // Emergency path still covers IPv4 and IPv6 symmetrically.
    assert!(
        runner.contains("iptables -t mangle -D PREROUTING")
            && runner.contains("ip6tables -t mangle -D PREROUTING")
            && runner.contains("ip rule del priority 101 lookup 33135")
            && runner.contains("ip -6 rule del priority 101 lookup 33135")
            && runner.contains("ip route del local 0.0.0.0/0")
            && runner.contains("ip -6 route del local ::/0"),
        "emergency destroy must cover v4/v6 chains, jumps, rules, and routes"
    );
    assert!(
        readme.contains("FERRUM_HOST_UDP_LIVE_EMERGENCY_DESTROY_CANONICAL")
            && readme.contains("never armed by ordinary exits"),
        "README must document the emergency destroy separately from ordinary runs"
    );
    assert!(
        !readme.contains("unconditionally removes Ferrum-owned host UDP state")
            && !readme.contains("tears that proxy's capture path down"),
        "README must not document an ordinary run as tearing down a live proxy"
    );
    assert!(
        readme.contains("disposable outer network namespace is the ordinary ownership boundary")
            && readme.contains("never enumerates or deletes")
            && readme.contains("structurally")
            && readme.contains("fresh read-only sysfs instance")
            && readme.contains("disposable veth probe"),
        "README must describe the outer-netns ownership boundary and structural proof"
    );

    // IPv4 and IPv6 live coverage stay pinned by the runner's pass counts.
    assert!(
        runner.contains("expected exactly 2 ambient host-UDP lib live tests")
            && runner.contains("expected exactly 1 ambient host-UDP functional live test"),
        "runner must keep dual-stack live pass-count pins"
    );
}

/// #3804: hosted execution must enforce the disposable outer netns boundary
/// without rewriting the trusted relevance block owned by PR #3800.
#[test]
fn ambient_host_udp_live_workflow_enforces_outer_netns_without_touching_relevance() {
    let workflow = read(".github/workflows/ambient-host-udp-live.yml");

    assert!(
        workflow.contains("unshare --net")
            && workflow
                .contains("Explicit hosted disposable outer network-namespace boundary (#3804)"),
        "hosted live execution must wrap run.sh in a disposable outer netns"
    );
    assert!(
        !workflow.contains("FERRUM_HOST_UDP_LIVE_IN_OUTER_NETNS"),
        "hosted workflow must not rely on a forgeable IN_OUTER_NETNS env flag"
    );
    assert!(
        workflow.contains("trusted relevance / `changes` job above")
            && workflow.contains("is untouched"),
        "the outer-netns wrap must document composition with the #3800 relevance freeze"
    );
    // Relevance block markers from the trusted-base classifier must remain.
    assert!(
        workflow.contains("git cat-file blob \"$entry_object\" > \"$trusted_filter\"")
            && workflow.contains("python3 -I \"$trusted_filter\" --self-test")
            && !workflow.contains("python3 .github/scripts/live_suite_path_filter.py"),
        "the trusted relevance block must remain intact"
    );
}

#[test]
fn ambient_host_udp_live_kernel_module_uses_production_scripts_and_skip_or_fail() {
    let live = read("src/proxy/host_udp_capture_live_tests.rs");
    assert!(
        live.contains("IptablesPlan::host_udp_setup_script"),
        "live gate must install via production host UDP setup script"
    );
    assert!(
        live.contains("IptablesPlan::host_udp_teardown_script"),
        "live gate must tear down via production host UDP teardown script"
    );
    assert!(
        live.contains("bind_mesh_udp_capture_socket_with_pktinfo"),
        "live gate must bind the production pktinfo capture socket"
    );
    assert!(
        live.contains("FERRUM_LIVE_TESTS_REQUIRED"),
        "live gate must use the shared skip-or-fail contract"
    );
    assert!(
        live.contains("skip_or_fail"),
        "live gate must convert missing prerequisites via skip_or_fail"
    );
    assert!(
        live.contains("SourceAddressMismatch"),
        "live gate must prove source spoofing refusal"
    );
    assert!(
        live.contains("AmbiguousInterface"),
        "live gate must prove ambiguous-interface refusal"
    );
    assert!(
        live.contains("redact_diag"),
        "live diagnostics must be redacted"
    );
    assert!(
        live.contains("DIAG_CAP"),
        "live diagnostics must be bounded"
    );

    let functional = read("tests/functional/functional_mesh_mode_test.rs");
    assert!(
        functional.contains("FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED"),
        "the process-level gate must select the production host-netns backend"
    );
    assert!(
        functional.contains("std::net::IpAddr::V4(pod_a.pod_v4)")
            && functional.contains("std::net::IpAddr::V6(pod.pod_v6)")
            && functional.contains("VIP_V6"),
        "the production backend gate must send dual-stack traffic from enrolled pod addresses"
    );
}

/// Host-UDP shutdown's gate-close wait must finish (and still have time for
/// fail-closed guard install + capture teardown) inside mesh mode's background
/// drain. A longer wait is aborted mid-handshake: the listener dies with the
/// process while Ferrum-owned v4/v6 jumps and fwmark routes remain installed —
/// the exact `ProxyHostUdpBackend` live-gate failure mode on #3705.
#[test]
fn host_udp_shutdown_ack_wait_fits_inside_mesh_background_drain() {
    let host_udp = read("src/proxy/host_udp_capture.rs");
    let mesh = read("src/modes/mesh/mod.rs");

    assert!(
        host_udp.contains("const GATE_CLOSE_ACK_TIMEOUT: Duration = Duration::from_secs(1);"),
        "host-UDP shutdown ack wait must stay at the 1s pod-netns ceiling so \
         teardown still runs under the mesh background drain"
    );
    assert!(
        host_udp.contains("gate_close_timeout.min(GATE_CLOSE_ACK_TIMEOUT)"),
        "shutdown must cap the acknowledgement wait even when a test raises the field"
    );
    assert!(
        host_udp.contains("teardown_capture_rules()")
            && host_udp.contains("preserving a fail-closed shutdown posture"),
        "the unacknowledged shutdown path must still retire capture jumps/routes"
    );
    assert!(
        mesh.contains(
            "const MESH_STARTUP_BACKGROUND_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);"
        ),
        "mesh background drain budget is the hard ceiling the host-UDP wait must fit under"
    );

    // Keep the numeric relationship explicit so a future edit that raises the
    // ack wait without raising the drain (or vice versa) fails this contract.
    const HOST_UDP_SHUTDOWN_ACK_SECS: u64 = 1;
    const MESH_BACKGROUND_DRAIN_SECS: u64 = 5;
    const {
        assert!(
            HOST_UDP_SHUTDOWN_ACK_SECS < MESH_BACKGROUND_DRAIN_SECS,
            "host-UDP shutdown ack wait must leave room inside the mesh background drain for \
             guard install and capture teardown"
        );
    }
}

/// Return the INSTRUCTIONS of a single `FROM ... AS <stage>` block, up to the
/// next `FROM`. Comment lines are stripped: the trailing comment block of a
/// stage documents the NEXT stage, so an absence assertion over raw text would
/// read a neighbouring stage's prose as this stage's content.
fn dockerfile_stage_body(dockerfile: &str, stage: &str) -> String {
    let marker = format!(" AS {stage}\n");
    let start = dockerfile
        .find(&marker)
        .unwrap_or_else(|| panic!("Dockerfile has no `AS {stage}` stage"))
        + marker.len();
    let rest = &dockerfile[start..];
    let body = match rest.find("\nFROM ") {
        Some(end) => &rest[..end],
        None => rest,
    };
    body.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The Ambient UDP lifecycle executes generated `sh -c` iptables/ip6tables
/// scripts, so the image the chart selects for it must ship those tools. It gets
/// its OWN published variant rather than weakening the distroless `-ebpf`
/// contract that the node-agent and NodeWaypoint still depend on (#3705).
#[test]
fn dockerfile_publishes_a_tools_capable_runtime_without_weakening_ebpf() {
    let dockerfile = read("Dockerfile");

    assert!(
        dockerfile.contains("AS capture-tools-base\n"),
        "the tool provisioning must live in its own stage so CI can smoke the \
         tool contract without the Rust and nightly eBPF builds"
    );
    assert!(
        dockerfile.contains("AS runtime-ebpf-tools\n"),
        "the Ambient UDP lifecycle runtime target must exist"
    );

    let tools_base = dockerfile_stage_body(&dockerfile, "capture-tools-base");
    assert!(
        tools_base.contains("iptables"),
        "the tool base must install iptables"
    );
    assert!(
        tools_base.contains("${IPROUTE2_VERSION}"),
        "the tool base must share the pinned iproute2 version with the \
         distroless staging closure"
    );
    assert!(
        tools_base.contains("for tool in ip iptables ip6tables iptables-save ip6tables-save; do"),
        "the tool base must assert the complete production tool set at build \
         time, so a missing tool fails the build instead of a node"
    );
    assert!(
        tools_base.contains("test -x /bin/sh"),
        "the tool base must assert a usable shell at build time"
    );

    let tools_runtime = dockerfile_stage_body(&dockerfile, "runtime-ebpf-tools");
    assert!(
        dockerfile.contains("FROM capture-tools-base AS runtime-ebpf-tools"),
        "the published tools runtime must inherit exactly the smoked tool base"
    );
    assert!(
        tools_runtime.contains("/app/bpf/ferrum-ebpf"),
        "the tools runtime must be a strict superset of `-ebpf` and carry the BPF ELF"
    );
    assert!(
        tools_runtime.contains("/app/ferrum-edge"),
        "the tools runtime must carry the gateway binary"
    );

    // The complementary half: `-ebpf` must stay distroless. A future change must
    // not "solve" the Ambient UDP tool requirement by adding a shell here.
    let ebpf_runtime = dockerfile_stage_body(&dockerfile, "runtime-ebpf");
    assert!(
        !ebpf_runtime.contains("iptables"),
        "the published `-ebpf` image must not gain iptables"
    );
    assert!(
        !ebpf_runtime.contains("/bin/sh"),
        "the published `-ebpf` image must not gain a shell"
    );
    assert!(
        ebpf_runtime.contains("/usr/sbin/ip"),
        "the published `-ebpf` image must keep its staged `ip` executable"
    );
}

/// A chart that names a tag the release pipeline never publishes is the same
/// outage as a chart that names an image without the tools. Both halves are
/// pinned here.
#[test]
fn ambient_udp_lifecycle_selects_the_tools_capable_published_runtime() {
    let chart = read("charts/ferrum-mesh/templates/ambient-daemonset.yaml");
    assert!(
        chart.contains(
            "{{- $ambientImageTag = printf \"%s-ebpf-tools\" \
             (trimSuffix \"-ebpf\" $ambientImageTag) -}}"
        ),
        "the Ambient UDP lifecycle must select the tools-capable runtime variant, \
         promoting an explicit `-ebpf` tag rather than double-suffixing it"
    );
    assert!(
        chart.contains("{{- if $ambientUdpLifecycle -}}"),
        "the tools variant must be selected by the UDP lifecycle predicate"
    );
    assert!(
        !chart.contains(
            "(eq $ambientTopology \"node_waypoint\") $ambientUdpLifecycle) \
             (not (hasSuffix \"-ebpf\" $ambientImageTag))"
        ),
        "the UDP lifecycle must no longer be folded into the distroless `-ebpf` \
         selection, which cannot run the production host-UDP backend"
    );

    // The node-agent keeps the distroless variant: only the pod that shells out
    // receives the larger attack surface.
    let node_agent = read("charts/ferrum-mesh/templates/node-agent-daemonset.yaml");
    assert!(
        node_agent.contains("printf \"%s-ebpf\" $nodeAgentImageTag"),
        "the node-agent must keep selecting the distroless `-ebpf` variant"
    );
    assert!(
        !node_agent.contains("-ebpf-tools"),
        "the node-agent must not silently adopt the tools-capable image"
    );

    let release = read(".github/workflows/release.yml");
    assert!(
        release.contains("target: runtime-ebpf-tools"),
        "the release pipeline must build the tools-capable runtime target"
    );
    for registry_tag in [
        "-t ferrumedge/ferrum-edge:${{ steps.version.outputs.TAG_NAME }}-ebpf-tools",
        "-t ghcr.io/${{ github.repository }}:${{ steps.version.outputs.TAG_NAME }}-ebpf-tools",
    ] {
        assert!(
            release.contains(registry_tag),
            "the release pipeline must publish `{registry_tag}` so the chart's \
             automatic selection can never name a nonexistent image"
        );
    }
    assert!(
        release.contains("docker-ebpf-tools-digest-${{ matrix.arch_dir }}"),
        "the tools variant must publish its own per-architecture digest artifact"
    );
    assert!(
        release.contains("pattern: docker-ebpf-tools-digest-*")
            && release.contains("path: /tmp/digests-tools"),
        "the tools digests must be collected separately so the two variants' \
         manifests cannot be merged into one four-descriptor list"
    );
    // Gating parity with the `-ebpf` manifest job. The tools manifest lives in
    // its own job so each tag family keeps its own frozen assembly contract and
    // its own digest name space, which makes the equivalence explicit here.
    assert!(
        release.contains(
            "    needs: [build-release-binaries, docker-manifest, docker-ebpf, \
             docker-ebpf-manifest]\n"
        ),
        "the tools manifest must be gated on the core release path AND on the \
         `-ebpf` manifest, so a release can never advertise the tools tag \
         without the variant it is a superset of"
    );
    assert!(
        release.contains("docker-ebpf-tools-manifest:\n"),
        "the tools manifest job must exist"
    );
}

/// A published image the chart selects in production must carry the SAME release
/// trust guarantees as the other two families. An image family that is gated and
/// tagged but not owned, signed, and attested is a supply-chain hole exactly
/// where the most privileged runtime (root, full Debian userland) ships.
#[test]
fn ambient_udp_lifecycle_image_is_a_first_class_trusted_release_family() {
    let release = read(".github/workflows/release.yml");
    let policy = read(".github/scripts/verify_cross_build_policy.py");
    let attestations = read(".github/scripts/verify_release_image_attestations.py");

    // 1. Release publication is gated on the tools manifest, so the notes can
    //    never advertise a tag whose manifest assembly failed.
    assert!(
        release.contains(
            "    needs: [build-release-binaries, build-release-arm64-cross, \
             docker-manifest, docker-ebpf-manifest, docker-ebpf-tools-manifest]\n"
        ),
        "create-release must depend on the tools manifest"
    );
    for advertised in [
        "docker pull ferrumedge/ferrum-edge:$TAG_NAME-ebpf-tools",
        "docker pull ghcr.io/ferrum-edge/ferrum-edge:$TAG_NAME-ebpf-tools",
    ] {
        assert!(
            release.contains(advertised),
            "the release notes must advertise the family they now gate on: \
             missing `{advertised}`"
        );
    }

    // 2. Signing and attestation cover the third family in both registries.
    assert!(
        release.contains(
            "    needs: [docker-manifest, docker-ebpf-manifest, \
             docker-ebpf-tools-manifest]\n"
        ),
        "attest-release-images must depend on the tools manifest so it signs a \
         manifest that actually exists"
    );
    for invocation in [
        "resolve_manifest ebpftools_docker",
        "resolve_manifest ebpftools_ghcr",
        "compare_registry_manifests ebpftools",
        "sign_and_attest ebpftools docker \"$EBPF_TOOLS_DOCKER_REF\"",
        "sign_and_attest ebpftools ghcr \"$EBPF_TOOLS_GHCR_REF\"",
        "verify_image ebpftools docker \"$EBPF_TOOLS_DOCKER_REF\"",
        "verify_image ebpftools ghcr \"$EBPF_TOOLS_GHCR_REF\"",
        "ebpftools docker \"$EBPF_TOOLS_DOCKER_REF\"",
        "ebpftools ghcr \"$EBPF_TOOLS_GHCR_REF\"",
        "$work/ebpftools_docker.provenance.json",
        "$work/ebpftools_ghcr.provenance.json",
    ] {
        assert!(
            release.contains(invocation),
            "the attestation job must cover the tools family: missing \
             `{invocation}`"
        );
    }

    // 3. The static release-attestation contract enforces the third family
    //    itself, so a later edit that drops it fails required CI rather than
    //    silently shipping an unsigned image.
    assert!(
        attestations.contains("(\"ebpftools\", \"-ebpf-tools\", \"EBPF_TOOLS\")"),
        "the release attestation contract must enumerate the tools family"
    );
    assert!(
        attestations.contains("\"docker-ebpf-tools-manifest\","),
        "the release attestation contract must require the tools manifest in \
         both the create-release and attestation dependency sets"
    );
    for mutation in [
        "tools-image signing",
        "tools-image SBOM generation",
        "tools-image attestation verification",
        "tools-image cross-registry manifest comparison",
        "tools-image canonical tag resolution",
    ] {
        assert!(
            attestations.contains(mutation),
            "the contract self-test must prove it rejects a dropped \
             `{mutation}` step"
        );
    }

    // 4. The digest name space is owned, and both the producing steps and the
    //    whole assembling job are frozen by the trusted cross-build policy's
    //    admitted three-family generation (PR #3768). Ownership is expressed
    //    through `RELEASE_TOOLS_DIGEST_PREFIX` rather than an inline literal so
    //    the two-family base and the three-family adoption stay in sync.
    assert!(
        policy.contains("RELEASE_TOOLS_DIGEST_PREFIX = \"docker-ebpf-tools-digest-\""),
        "the tools digest wildcard prefix must be named exactly once"
    );
    assert!(
        policy.contains("RELEASE_TOOLS_DIGEST_PREFIX: (\"docker-ebpf\",),"),
        "the tools digest wildcard must be owned by exactly the docker-ebpf job, \
         so no other job can inject a descriptor into the published manifest"
    );
    assert!(
        policy.contains("RELEASE_THREE_FAMILY_DIGEST_ARTIFACT_OWNERS"),
        "digest ownership for the tools family must live in the three-family \
         adoption generation, not silently rewrite the two-family base"
    );
    for frozen in [
        "\"Build and push per-platform eBPF tools digest\": (",
        "\"Upload tools digest\": DOCKER_EBPF_TOOLS_UPLOAD_DIGEST_STEP,",
        "\"Download tools digests\": (",
        "DOCKER_EBPF_MANIFEST_TOOLS_DOWNLOAD_STEP",
        "\"steps\": RELEASE_DOCKER_EBPF_TOOLS_MANIFEST_STEPS,",
        "RELEASE_IMAGE_FAMILY_GENERATIONS",
    ] {
        assert!(
            policy.contains(frozen),
            "the trusted publication contract must freeze `{frozen}`"
        );
    }
    assert!(
        policy.contains("needs: [build-release-binaries, build-release-arm64-cross, ")
            && policy.contains("docker-ebpf-tools-manifest]\\n"),
        "the frozen create-release dependency contract must include the tools \
         manifest"
    );

    // 5. Editing any of those trusted surfaces must schedule this required gate.
    let filter = read(".github/scripts/live_suite_path_filter.py");
    assert!(
        filter.contains("verify_release_image_attestations"),
        "a release-trust verifier edit must schedule the Ambient host UDP gate"
    );

    // 6. The documentation must not describe the family as an unattested gap.
    let ci_docs = read("docs/ci_cd.md");
    assert!(
        !ci_docs.contains("`-ebpf-tools` is published but not yet signed/attested"),
        "the known-gap characterization must not outlive the gap"
    );
    assert!(
        ci_docs.contains("standard, `-ebpf`, and\n`-ebpf-tools`"),
        "the release-trust documentation must describe three signed families"
    );
}

/// The live-kernel job runs prebuilt binaries on the hosted runner, so it proves
/// the RUNNER's package set. The production image contract is what proves the
/// runtime the chart actually selects can execute the same tools.
#[test]
fn ambient_host_udp_gate_proves_the_production_image_tool_contract() {
    let workflow = read(".github/workflows/ambient-host-udp-live.yml");

    assert!(
        workflow.contains("  ambient-host-udp-image:\n"),
        "the gate must carry a production image contract job"
    );
    assert!(
        workflow.contains("target: runtime-ebpf-tools"),
        "the image job must build the EXACT production target the chart selects"
    );
    assert!(
        workflow.contains("target: capture-tools-base"),
        "the image job must smoke the tool base before the expensive builds"
    );
    assert!(
        workflow.contains("for tool in ip iptables ip6tables iptables-save ip6tables-save; do"),
        "the image job must prove the full production tool set executes"
    );
    assert!(
        workflow.contains("--entrypoint /bin/sh ferrum-edge-ebpf-tools:ci"),
        "the image job must prove the selected image can execute a shell, which \
         is what the generated capture scripts require"
    );
    assert!(
        workflow.contains("test -s /app/bpf/ferrum-ebpf"),
        "the image job must prove the tools image is a superset of `-ebpf`"
    );
    assert!(
        workflow.contains("target: runtime-ebpf")
            && workflow.contains("the distroless -ebpf image must not ship"),
        "the image job must independently prove `-ebpf` stayed distroless, so \
         this contract cannot be satisfied by weakening that image instead"
    );
    assert!(
        workflow.contains("      - ambient-host-udp-image\n"),
        "the required gate must depend on the image contract job"
    );
    assert!(
        workflow.contains("${{ needs.ambient-host-udp-image.result }}\" != \"success\""),
        "the required gate must fail when the image contract fails or is absent"
    );
}

#[test]
fn image_surfaces_are_scheduled_by_the_trusted_relevance_classifier() {
    let filter = read(".github/scripts/live_suite_path_filter.py");
    assert!(
        filter.contains("r\"^Dockerfile$\""),
        "a Dockerfile edit can change whether the chart-selected runtime ships \
         the capture tools, so it must schedule this gate"
    );
    assert!(
        filter.contains("ambient-host-udp-live|release"),
        "a release-publication edit can retire the tag the chart selects"
    );
    assert!(
        filter.contains("r\"^\\.github/scripts/stage_iproute2_runtime\\.sh$\""),
        "the runtime tool staging helper must schedule this gate"
    );
    assert!(
        filter.contains("(\"ambient-host-udp\", [\"Dockerfile\"], True)"),
        "the trusted classifier self-test must pin the Dockerfile trigger"
    );

    let plan = read(".github/scripts/pr_ci_plan.py");
    assert!(
        plan.contains("r\"^Dockerfile$\""),
        "the planner's eBPF/capture live patterns must include the Dockerfile"
    );
}

#[test]
fn pr_ci_plan_schedules_ebpf_live_for_host_udp_surfaces() {
    let plan = read(".github/scripts/pr_ci_plan.py");
    assert!(
        plan.contains("host_udp_capture"),
        "planner eBPF/netns live patterns must include host_udp_capture"
    );
    assert!(
        plan.contains("ambient_host_udp_live"),
        "planner must include the ambient host-UDP live fixture path"
    );
    assert!(
        plan.contains("ambient-host-udp-live"),
        "planner must treat the ambient host-UDP workflow as a live trigger"
    );
    assert!(
        plan.contains("[\"src/proxy/host_udp_capture.rs\"]"),
        "planner self-test must pin host_udp_capture as run_ebpf_live"
    );
}
