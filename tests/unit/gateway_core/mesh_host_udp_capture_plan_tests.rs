//! Host-network UDP capture rule-plan contracts (issue #3288).
//!
//! The host path exists because the pod-netns generator's `-m addrtype
//! --dst-type LOCAL` direction split is meaningless in the host namespace. These
//! tests pin the properties that make the replacement safe, because every one of
//! them is a silent security regression if it is lost:
//!
//! * direction is decided by INGRESS INTERFACE, per enrolled pod;
//! * the node's own traffic is structurally uncapturable (no `OUTPUT` chain);
//! * inbound-to-pod traffic is untouched (no `--dst-type LOCAL` catch-all);
//! * interface names are validated before they reach a shell script;
//! * host and pod-netns state own disjoint objects, so neither teardown can
//!   remove the other's rules or routing.

use ferrum_edge::capture::{
    CaptureConfig, Ip6TablesMode, IptablesPlan, MAX_HOST_UDP_CAPTURE_INTERFACES,
    UdpCaptureSettings, udp_capture_settings_from_env, validate_host_capture_interface,
    validate_host_capture_interfaces,
};
use ferrum_edge::modes::mesh::{MeshTopology, validate_udp_host_netns_placement};

use crate::unit::env_lock::EnvGuard;

const UDP_ENV_KEYS: &[&str] = &[
    "FERRUM_MESH_CAPTURE_UDP_ENABLED",
    "FERRUM_MESH_CAPTURE_UDP_PORT",
    "FERRUM_MESH_TPROXY_MARK",
    "FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED",
];

fn host_config() -> CaptureConfig {
    let mut config = CaptureConfig::explicit(15006, 15001);
    config.udp_capture_enabled = true;
    // The mesh proxy sets this for the host placement; it selects which rule
    // generator is valid rather than suppressing UDP capture.
    config.host_netns = true;
    config.proxy_uid = None;
    config
}

fn ifaces(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_string()).collect()
}

#[test]
fn host_udp_plan_scopes_every_capture_rule_to_an_enrolled_interface() {
    let plan = IptablesPlan::host_udp_for_config(&host_config(), &ifaces(&["vetha", "vethb"]))
        .expect("valid host plan");

    let tproxy_rules: Vec<&String> = plan
        .v4_commands
        .iter()
        .filter(|cmd| cmd.contains("-j TPROXY"))
        .collect();
    assert_eq!(
        tproxy_rules.len(),
        2,
        "one TPROXY rule per enrolled interface: {:#?}",
        plan.v4_commands
    );
    for rule in &tproxy_rules {
        assert!(
            rule.contains("-i vetha ") || rule.contains("-i vethb "),
            "every TPROXY rule must carry an ingress-interface scope: {rule}"
        );
        assert!(
            rule.contains("--on-port 15011"),
            "TPROXY must target the capture port: {rule}"
        );
    }
}

#[test]
fn host_udp_plan_never_captures_node_traffic_or_inbound_to_pod() {
    let plan =
        IptablesPlan::host_udp_for_config(&host_config(), &ifaces(&["vetha"])).expect("valid plan");
    let all = plan.v4_commands.join("\n");

    // Locally generated traffic — kubelet, CNI, DNS, the proxy's own relay
    // egress, every hostNetwork pod — only traverses OUTPUT. Emitting NO OUTPUT
    // chain is what makes host traffic structurally uncapturable, so this is the
    // single most load-bearing assertion in the file.
    assert!(
        !all.contains("OUTPUT"),
        "the host path must install no `mangle OUTPUT` chain or jump: {all}"
    );
    assert!(
        !all.contains("FERRUM_MESH_UDP_OUTPUT_MARK") && !all.contains("-j MARK"),
        "the host path must not mark locally generated traffic: {all}"
    );
    // Inbound-to-pod UDP arrives on the node uplink, not on a pod interface, so
    // there is no inbound chain and no addrtype guesswork at all.
    assert!(
        !all.contains("addrtype"),
        "the host path must not use an addrtype direction split: {all}"
    );
    assert!(
        !all.contains("FERRUM_MESH_UDP_INBOUND"),
        "the host path must not install an inbound catch-all chain: {all}"
    );
    assert!(
        !all.contains("FERRUM_MESH_UDP_REINJECT"),
        "the host path has no OUTPUT-mark reinjection loop: {all}"
    );
}

#[test]
fn host_udp_plan_owns_objects_disjoint_from_the_pod_netns_path() {
    let plan =
        IptablesPlan::host_udp_for_config(&host_config(), &ifaces(&["vetha"])).expect("valid plan");
    let all = plan.v4_commands.join("\n");

    assert!(all.contains("FERRUM_MESH_UDP_HOST"), "{all}");
    assert!(
        !all.contains("FERRUM_MESH_UDP_OUTBOUND"),
        "the host chain must not share the pod-netns chain name: {all}"
    );
    // A shared routing table or rule priority would let one path's teardown rip
    // out the other's transparent delivery.
    assert!(
        all.contains("table 33135") && all.contains("priority 101"),
        "host routing must use the host-owned table/priority: {all}"
    );
    assert!(
        !all.contains("33133") && !all.contains("priority 100 "),
        "host routing must not touch the pod-netns table/priority: {all}"
    );
}

#[test]
fn host_udp_plan_installs_routing_before_the_prerouting_jump() {
    let plan =
        IptablesPlan::host_udp_for_config(&host_config(), &ifaces(&["vetha"])).expect("valid plan");

    let preflight = plan
        .v4_commands
        .iter()
        .position(|cmd| cmd.contains("command -v ip "))
        .expect("fatal iproute2 preflight");
    let route_add = plan
        .v4_commands
        .iter()
        .position(|cmd| cmd.starts_with("ip route add local"))
        .expect("local route add");
    let jump = plan
        .v4_commands
        .iter()
        .position(|cmd| cmd.contains("PREROUTING") && cmd.contains("-j FERRUM_MESH_UDP_HOST"))
        .expect("stable PREROUTING jump");

    assert_eq!(preflight, 0, "the `ip` preflight must precede every rule");
    assert!(
        route_add < jump,
        "policy routing must be live before the jump starts steering UDP, or captured \
         datagrams black-hole: route_add={route_add} jump={jump}"
    );
    assert!(
        plan.v4_commands[jump].contains("-p udp -j FERRUM_MESH_UDP_HOST")
            && !plan.v4_commands[jump].contains("-i "),
        "the PREROUTING jump must be interface-independent so reconciliation only ever \
         rewrites the chain's contents: {}",
        plan.v4_commands[jump]
    );
    // The load-bearing routing adds must NOT be best-effort: TPROXY without
    // policy routing is a silent black hole.
    assert!(
        !plan.v4_commands[route_add].contains("|| true"),
        "the local route add must fail closed: {}",
        plan.v4_commands[route_add]
    );
}

#[test]
fn host_udp_plan_with_no_enrolled_interfaces_captures_nothing_but_stays_installed() {
    let plan = IptablesPlan::host_udp_for_config(&host_config(), &[]).expect("valid empty plan");
    let all = plan.v4_commands.join("\n");

    assert!(
        !all.contains("-j TPROXY"),
        "an empty enrolled set must capture nothing: {all}"
    );
    assert!(
        all.contains("-j FERRUM_MESH_UDP_HOST"),
        "the chain and its stable jump still exist so the next reconcile is a pure \
         flush-and-repopulate: {all}"
    );
}

#[test]
fn host_udp_plan_rebuilds_the_chain_so_a_removed_pod_cannot_linger() {
    let plan = IptablesPlan::host_udp_for_config(&host_config(), &ifaces(&["vetha", "vethb"]))
        .expect("valid plan");
    let flush = plan
        .v4_commands
        .iter()
        .position(|cmd| cmd.contains("-F FERRUM_MESH_UDP_HOST"))
        .expect("chain flush");
    let first_rule = plan
        .v4_commands
        .iter()
        .position(|cmd| cmd.contains("-j TPROXY"))
        .expect("capture rule");
    assert!(
        flush < first_rule,
        "the chain must be flushed before it is repopulated, or an unenrolled pod's rule \
         would survive reconciliation"
    );
}

#[test]
fn host_udp_guard_drops_exactly_the_capture_scope_from_prerouting() {
    let script = IptablesPlan::host_udp_guard_script(&host_config(), &ifaces(&["vetha"]))
        .expect("valid guard");

    assert!(script.starts_with("set -e"), "{script}");
    // The guard must drop EXACTLY the scope capture would take: the same ingress
    // interface and the same configured destination scope, differing only in the
    // target. Deriving the expected match from the capture plan keeps the two
    // generators pinned together instead of restating one of them here.
    let capture = IptablesPlan::host_udp_for_config(&host_config(), &ifaces(&["vetha"]))
        .expect("valid host plan");
    let tproxy = capture
        .v4_commands
        .iter()
        .find(|cmd| cmd.contains("-j TPROXY"))
        .expect("capture rule");
    let scope = tproxy
        .split_once("-i vetha ")
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split_once(" -j "))
        .map(|(scope, _)| scope)
        .expect("interface-scoped capture rule");
    assert!(
        script.contains(&format!("-i vetha {scope} -j DROP")),
        "the guard must drop the same interface-scoped scope capture would take ({scope}): \
         {script}"
    );
    assert!(
        script.contains("FERRUM_MESH_UDP_HOST_GUARD_A")
            && script.contains("FERRUM_MESH_UDP_HOST_GUARD_B"),
        "the guard must alternate generations so a retry never flushes the live guard: {script}"
    );
    assert!(
        script.contains("-I PREROUTING 1"),
        "the host guard is jumped from PREROUTING (host-netns pod egress is forwarded and \
         never traverses OUTPUT): {script}"
    );
    assert!(
        !script.contains("-I OUTPUT 1") && !script.contains("-C OUTPUT"),
        "the host guard must never touch OUTPUT, which carries the node's own traffic: {script}"
    );
}

#[test]
fn host_udp_guard_is_empty_when_there_is_nothing_to_guard() {
    assert_eq!(
        IptablesPlan::host_udp_guard_script(&host_config(), &[]).expect("valid"),
        ""
    );
    let mut disabled = host_config();
    disabled.udp_capture_enabled = false;
    assert_eq!(
        IptablesPlan::host_udp_guard_script(&disabled, &ifaces(&["vetha"])).expect("valid"),
        ""
    );
}

#[test]
fn host_udp_teardown_reaps_only_host_owned_objects() {
    let script = IptablesPlan::host_udp_teardown_script();

    for expected in [
        "-D PREROUTING -p udp -j FERRUM_MESH_UDP_HOST",
        "-X FERRUM_MESH_UDP_HOST",
        "ip6tables -t mangle",
        "rule del priority 101 lookup 33135",
        "route del local 0.0.0.0/0 dev lo table 33135",
        "route del local ::/0 dev lo table 33135",
        "FERRUM_MESH_UDP_HOST_GUARD_A",
        "FERRUM_MESH_UDP_HOST_GUARD_B",
    ] {
        assert!(script.contains(expected), "missing {expected} in {script}");
    }
    // Never touch the pod-netns objects, the node-agent's ingress-redirect table
    // (33134), or a co-resident Istio install's table (133).
    for forbidden in [
        "FERRUM_MESH_UDP_OUTBOUND",
        "FERRUM_MESH_UDP_INBOUND",
        "FERRUM_MESH_UDP_OUTPUT_MARK",
        "FERRUM_MESH_UDP_REINJECT",
        "33133",
        "33134",
        "table 133",
        "flush table",
    ] {
        assert!(
            !script.contains(forbidden),
            "host teardown must not touch {forbidden}: {script}"
        );
    }
}

#[test]
fn host_udp_capture_rules_teardown_leaves_the_guard_in_place() {
    let script = IptablesPlan::host_udp_capture_rules_teardown_script();
    assert!(script.contains("-X FERRUM_MESH_UDP_HOST"), "{script}");
    assert!(
        !script.contains("FERRUM_MESH_UDP_HOST_GUARD_A"),
        "removing capture while retaining the DROP guard is the fail-closed retry posture: \
         {script}"
    );
}

#[test]
fn host_udp_guard_release_is_strict_about_resource_errors() {
    let script = IptablesPlan::host_udp_guard_release_script();
    assert!(script.starts_with("set -e"), "{script}");
    assert!(
        script.contains("could not check PREROUTING jump FERRUM_MESH_UDP_HOST_GUARD_A"),
        "a failed release must abort so readiness is never claimed behind a live DROP: {script}"
    );
}

/// Run a generated teardown script against an xtables shim whose rule check
/// always matches while every rule delete fails with status 4 (an xtables lock
/// held past `-w`). Returns `None` when the script is still running after the
/// deadline, which is the spin the strict jump-release loop must never enter.
#[cfg(unix)]
fn run_teardown_with_stuck_jump_delete(script: &str) -> Option<std::process::Output> {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    // Shell functions shadow the real binaries (and satisfy `command -v`), so
    // nothing here touches the host's netfilter or routing state. No `set -e`:
    // this is how the best-effort teardown scripts and the node-agent cleanup
    // runner execute.
    let harness = format!(
        r#"
iptables() {{
  case "$*" in
    *" -D "*) return 4 ;;
    *) return 0 ;;
  esac
}}
ip6tables() {{ iptables "$@"; }}
ip() {{ return 0; }}
{script}
"#
    );
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(harness)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sh");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if child.try_wait().expect("poll sh").is_some() {
            return Some(child.wait_with_output().expect("collect sh output"));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
#[test]
fn teardown_aborts_instead_of_spinning_when_a_jump_delete_keeps_failing() {
    for (name, script) in [
        ("host", IptablesPlan::host_udp_teardown_script()),
        ("pod-netns", IptablesPlan::udp_teardown_script(false)),
    ] {
        let output = run_teardown_with_stuck_jump_delete(&script).unwrap_or_else(|| {
            panic!("{name} teardown spun on a jump whose delete keeps failing:\n{script}")
        });
        assert_eq!(
            output.status.code(),
            Some(4),
            "{name} teardown must exit with the failed delete's status: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("could not delete"),
            "{name} teardown must report the failed jump delete: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn host_capture_interface_names_reject_shell_and_wildcard_injection() {
    assert!(validate_host_capture_interface("veth1234abcd").is_ok());
    assert!(validate_host_capture_interface("cali-abc.1").is_ok());

    // Rejected, in order: empty; the iptables prefix wildcard (`veth+` matches
    // every `veth*` interface — silent overreach); a bare wildcard; command
    // injection; command substitution; argument splitting; newline injection; a
    // name parsed as an iptables option; a path sentinel; and a 16-character name
    // over the kernel IFNAMSIZ limit.
    for hostile in [
        "",
        "veth+",
        "+",
        "veth;reboot",
        "veth$(id)",
        "veth a",
        "veth\nrm -rf /",
        "-j",
        "..",
        "veth012345678901",
    ] {
        assert!(
            validate_host_capture_interface(hostile).is_err(),
            "must reject {hostile:?}"
        );
    }
}

#[test]
fn host_capture_interface_set_rejects_duplicates_and_overflow() {
    assert!(validate_host_capture_interfaces(&ifaces(&["vetha", "vethb"])).is_ok());
    assert!(
        validate_host_capture_interfaces(&ifaces(&["vetha", "vetha"])).is_err(),
        "a duplicate would emit a rule teardown reaps only once"
    );

    let too_many: Vec<String> = (0..=MAX_HOST_UDP_CAPTURE_INTERFACES)
        .map(|index| format!("veth{index}"))
        .collect();
    assert!(validate_host_capture_interfaces(&too_many).is_err());
}

#[test]
fn host_udp_plan_refuses_a_hostile_interface_wholesale() {
    // Refusing the whole plan (rather than skipping the bad entry) is what keeps
    // a corrupt registry entry from yielding a partially-scoped ruleset that
    // silently captures a different set of pods than intended.
    let error = IptablesPlan::host_udp_for_config(&host_config(), &ifaces(&["vetha", "veth+"]))
        .expect_err("hostile interface must fail the plan");
    assert!(error.contains("interface name"), "{error}");

    let error = IptablesPlan::host_udp_setup_script(&host_config(), &ifaces(&["veth;id"]))
        .expect_err("hostile interface must fail the script");
    assert!(error.contains("interface name"), "{error}");
}

#[test]
fn host_udp_plan_requires_udp_capture_to_be_enabled() {
    let mut disabled = host_config();
    disabled.udp_capture_enabled = false;
    let error = IptablesPlan::host_udp_for_config(&disabled, &ifaces(&["vetha"]))
        .expect_err("must not silently emit nothing");
    assert!(error.contains("FERRUM_MESH_CAPTURE_UDP_ENABLED"), "{error}");
}

#[test]
fn host_udp_ipv6_rules_follow_the_configured_v6_scope() {
    let mut config = host_config();
    config.include_cidrs = vec!["0.0.0.0/0".to_string(), "::/0".to_string()];
    config.include_cidrs_explicit = true;
    let plan =
        IptablesPlan::host_udp_for_config(&config, &ifaces(&["vetha"])).expect("dual-stack plan");
    assert!(
        plan.v6_commands
            .iter()
            .any(|cmd| cmd.contains("ip6tables") && cmd.contains("-j TPROXY")),
        "{:#?}",
        plan.v6_commands
    );
    assert!(
        plan.v6_commands
            .iter()
            .any(|cmd| cmd.starts_with("ip -6 route add local ::/0")),
        "{:#?}",
        plan.v6_commands
    );

    let mut v6_disabled = config.clone();
    v6_disabled.ip6tables_mode = Ip6TablesMode::Disabled;
    let plan =
        IptablesPlan::host_udp_for_config(&v6_disabled, &ifaces(&["vetha"])).expect("v4-only plan");
    assert!(plan.v6_commands.is_empty());
}

#[test]
fn host_netns_switch_without_udp_capture_is_a_configuration_error() {
    let guard = EnvGuard::new(UDP_ENV_KEYS);
    for key in UDP_ENV_KEYS {
        guard.unset(key);
    }

    guard.set("FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED", "true");
    let error = udp_capture_settings_from_env()
        .expect_err("host placement without UDP capture must fail closed");
    assert!(
        error.contains("FERRUM_MESH_CAPTURE_UDP_ENABLED"),
        "the diagnostic must name the missing switch: {error}"
    );

    guard.set("FERRUM_MESH_CAPTURE_UDP_ENABLED", "true");
    let settings = udp_capture_settings_from_env().expect("consistent settings");
    assert!(settings.udp_capture_enabled);
    assert!(settings.udp_host_netns_enabled);

    guard.set("FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED", "yes");
    assert!(
        udp_capture_settings_from_env().is_err(),
        "the boolean parser stays strict (`yes` is not a supported form)"
    );

    guard.unset("FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED");
    let settings = udp_capture_settings_from_env().expect("default settings");
    assert!(
        !settings.udp_host_netns_enabled,
        "the pod-netns producer stays the default placement"
    );
}

fn udp_settings(host_netns_enabled: bool) -> UdpCaptureSettings {
    UdpCaptureSettings {
        udp_capture_enabled: true,
        udp_outbound_port: 15011,
        tproxy_mark: 0x733,
        udp_host_netns_enabled: host_netns_enabled,
    }
}

/// Every topology but Ambient. Ambient is the only one whose proxy runs OUTSIDE
/// the workload pod netns, which is the entire premise of the host placement.
const NON_AMBIENT_TOPOLOGIES: &[MeshTopology] = &[
    MeshTopology::Sidecar,
    MeshTopology::NodeWaypoint,
    MeshTopology::ServiceWaypoint,
    MeshTopology::EastWestGateway,
    MeshTopology::EgressGateway,
];

#[test]
fn host_netns_placement_outside_ambient_is_a_startup_error() {
    // `udp_capture_settings_from_env` is shared with the injector and the
    // node-agent, neither of which knows the topology, so the topology half of
    // the documented contract has to hold here — on the serving path — or a
    // direct-env deployment that never renders the chart silently starts with no
    // host capture producer while believing UDP is covered.
    for topology in NON_AMBIENT_TOPOLOGIES {
        let error = validate_udp_host_netns_placement(*topology, &udp_settings(true))
            .expect_err("the host placement is Ambient-only");
        assert!(
            error.contains("FERRUM_MESH_TOPOLOGY=ambient"),
            "the diagnostic must name the topology the placement requires: {error}"
        );
        assert!(
            error.contains("FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED"),
            "and the switch that has to be withdrawn: {error}"
        );
    }

    assert!(
        validate_udp_host_netns_placement(MeshTopology::Ambient, &udp_settings(true)).is_ok(),
        "Ambient is exactly the deployment this placement exists for"
    );
    for topology in NON_AMBIENT_TOPOLOGIES {
        assert!(
            validate_udp_host_netns_placement(*topology, &udp_settings(false)).is_ok(),
            "the default placement stays valid everywhere: {topology:?}"
        );
    }
}
