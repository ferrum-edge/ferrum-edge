//! NodeWaypoint UDP/DTLS Service-path steering contracts (issue #3286).
//!
//! The steering datapath installs kernel objects that OUTLIVE the process that
//! installed them, and it decides which enrolled interfaces have their Service
//! traffic diverted to a materialized listener. Both properties fail silently
//! when they fail, so they are pinned here rather than left to the live gate:
//!
//! * a crashed predecessor's rules are reaped on this process's FIRST pass,
//!   even when this generation steers nothing;
//! * a later quiet poll runs no command at all;
//! * a failed apply leaves the datapath torn down by exact name, and the whole
//!   plan is retried on the next reconcile;
//! * the emitted command ORDER never marks a datagram under a destination
//!   generation whose notrack / local-delivery prerequisites are not installed;
//! * a published address family that cannot be installed fails the WHOLE apply
//!   instead of being silently skipped.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use ferrum_edge::capture::{
    NodeWaypointUdpSteerDestination, node_waypoint_udp_steer_setup_script,
    node_waypoint_udp_steer_teardown_script,
};
use ferrum_edge::proxy::node_waypoint_udp_reply_source::{
    NodeWaypointUdpReplySourcePublisher, RegistryDirReplySourcePublisher, ReplySourceGeneration,
    clear_acknowledgement, read_desired_generation, write_acknowledgement,
};
use ferrum_edge::proxy::node_waypoint_udp_steering::{
    NodeWaypointUdpSteerBackend, NodeWaypointUdpSteering, SteerReconcileOutcome,
};

/// The publishing NodeWaypoint proxy's own pod identity. The node-agent
/// resolves it host-side into the relay cgroup set that makes a UDP relay
/// datagram provable (issues #3956, #3957).
const RELAY_POD_UID: &str = "11111111-2222-3333-4444-555555555555";

/// Records every script the reconcile runs, and can fail on demand.
struct RecordingBackend {
    scripts: Mutex<Vec<String>>,
    fail_setup: bool,
}

impl RecordingBackend {
    fn new(fail_setup: bool) -> Arc<Self> {
        Arc::new(Self {
            scripts: Mutex::new(Vec::new()),
            fail_setup,
        })
    }

    fn scripts(&self) -> Vec<String> {
        self.scripts.lock().expect("recording backend lock").clone()
    }

    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.scripts.lock().expect("recording backend lock"))
    }
}

impl NodeWaypointUdpSteerBackend for RecordingBackend {
    fn run_script(&self, script: &str) -> Result<(), String> {
        self.scripts
            .lock()
            .expect("recording backend lock")
            .push(script.to_string());
        // Only a SETUP script can fail here; the teardown is the recovery path
        // and must be observed to run.
        if self.fail_setup && script.contains("--set-xmark") {
            return Err("boom".to_string());
        }
        Ok(())
    }
}

fn destination(ip: &str, port: u16) -> NodeWaypointUdpSteerDestination {
    NodeWaypointUdpSteerDestination {
        ip: ip.parse::<IpAddr>().expect("destination address"),
        port,
    }
}

#[test]
fn steering_refuses_non_unicast_service_destinations() {
    for address in [
        "0.0.0.0",
        "127.0.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "ff02::1",
    ] {
        let error = node_waypoint_udp_steer_setup_script(
            &["veth0".to_string()],
            &[destination(address, 5353)],
        )
        .expect_err("a non-unicast address must refuse the whole steering plan");
        assert!(
            error.contains("refuses an unspecified, loopback, multicast, or IPv4 broadcast"),
            "unexpected refusal for {address}: {error}"
        );
    }
}

fn is_teardown(script: &str) -> bool {
    script.contains("ferrum_delete_xtables_rule")
}

/// A `Drop` on `NodeWaypointUdpSteering` runs one final teardown, which would
/// pollute the recorded script list of a test that asserts on totals. Leak the
/// object deliberately instead of asserting around that final call.
fn forget(steering: NodeWaypointUdpSteering) {
    std::mem::forget(steering);
}

// ── First-pass reaping ─────────────────────────────────────────────────────

/// The regression this exists for: Ferrum-owned chains, `ip rule`s, and routes
/// survive the process that installed them. A process that starts after a crash
/// and computes an EMPTY plan must still reap them on its first pass — the old
/// `applied.is_none() => Unchanged` short-circuit left a crashed predecessor's
/// destinations marked and locally delivered to a socket that no longer exists,
/// for the whole life of the new process.
#[test]
fn the_first_reconcile_reaps_a_previous_process_even_with_an_empty_plan() {
    let backend = RecordingBackend::new(false);
    let steering = NodeWaypointUdpSteering::new(backend.clone());

    assert_eq!(
        steering.reconcile_with(&["veth0".to_string()], &[], false),
        SteerReconcileOutcome::Removed,
        "an empty destination plan on the FIRST pass must still tear the node down"
    );
    let scripts = backend.take();
    assert_eq!(scripts.len(), 1, "exactly one teardown, not a setup");
    assert!(
        is_teardown(&scripts[0]),
        "the first pass must run the exact-name teardown: {}",
        scripts[0]
    );
    assert_eq!(
        scripts[0],
        node_waypoint_udp_steer_teardown_script(),
        "the reaped objects are named exactly, never matched by pattern"
    );
    forget(steering);
}

/// The other empty half — no attributable interface — is the same posture and
/// must reap on the first pass too.
#[test]
fn the_first_reconcile_reaps_when_no_interface_is_attributable() {
    let backend = RecordingBackend::new(false);
    let steering = NodeWaypointUdpSteering::new(backend.clone());

    assert_eq!(
        steering.reconcile_with(&[], &[destination("10.96.0.10", 5300)], false),
        SteerReconcileOutcome::Removed
    );
    let scripts = backend.take();
    assert_eq!(scripts.len(), 1);
    assert!(is_teardown(&scripts[0]));
    forget(steering);
}

/// …and having reaped once, every later quiet poll must run NOTHING. Otherwise
/// the fix would trade a stale-rule leak for an `iptables` invocation on every
/// registry poll for the life of the process.
#[test]
fn later_empty_reconciles_are_idempotent_and_run_no_command() {
    let backend = RecordingBackend::new(false);
    let steering = NodeWaypointUdpSteering::new(backend.clone());

    assert_eq!(
        steering.reconcile_with(&[], &[], false),
        SteerReconcileOutcome::Removed
    );
    assert_eq!(backend.take().len(), 1, "the first pass reaps");

    for _ in 0..5 {
        assert_eq!(
            steering.reconcile_with(&[], &[], false),
            SteerReconcileOutcome::Unchanged
        );
    }
    assert!(
        backend.scripts().is_empty(),
        "a quiet poll after a proven teardown must run no command"
    );
    forget(steering);
}

/// An unchanged NON-empty generation is likewise a no-op after it is applied.
#[test]
fn an_unchanged_generation_runs_no_command_after_it_is_applied() {
    let backend = RecordingBackend::new(false);
    let steering = NodeWaypointUdpSteering::new(backend.clone());
    let ifaces = vec!["veth0".to_string()];
    let destinations = vec![destination("10.96.0.10", 5300)];

    assert_eq!(
        steering.reconcile_with(&ifaces, &destinations, true),
        SteerReconcileOutcome::Applied
    );
    let first = backend.take();
    assert_eq!(
        first.len(),
        2,
        "the first apply reaps a possible predecessor, then installs"
    );
    assert!(is_teardown(&first[0]));
    assert!(!is_teardown(&first[1]));

    for _ in 0..3 {
        assert_eq!(
            steering.reconcile_with(&ifaces, &destinations, true),
            SteerReconcileOutcome::Unchanged
        );
    }
    assert!(backend.scripts().is_empty());
    forget(steering);
}

/// A failed apply must leave the datapath torn down by exact name AND must not
/// record the plan as applied, so the next reconcile retries the whole thing
/// rather than reporting a black hole as steady state.
#[test]
fn a_failed_apply_tears_down_and_is_retried_on_the_next_reconcile() {
    let backend = RecordingBackend::new(true);
    let steering = NodeWaypointUdpSteering::new(backend.clone());
    let ifaces = vec!["veth0".to_string()];
    let destinations = vec![destination("10.96.0.10", 5300)];

    assert_eq!(
        steering.reconcile_with(&ifaces, &destinations, true),
        SteerReconcileOutcome::Failed
    );
    let first = backend.take();
    assert!(
        is_teardown(first.last().expect("a teardown ran")),
        "a failed apply must be followed by the exact-name teardown"
    );

    assert_eq!(
        steering.reconcile_with(&ifaces, &destinations, true),
        SteerReconcileOutcome::Failed,
        "the identical plan must be attempted again, not reported Unchanged"
    );
    assert!(
        backend.scripts().iter().any(|s| !is_teardown(s)),
        "the retry must actually re-run the setup script"
    );
    forget(steering);
}

// ── Emitted command order and fail-closed family handling ──────────────────

fn setup_script(ifaces: &[&str], destinations: &[NodeWaypointUdpSteerDestination]) -> String {
    let ifaces: Vec<String> = ifaces.iter().map(|iface| (*iface).to_string()).collect();
    node_waypoint_udp_steer_setup_script(&ifaces, destinations)
        .expect("the plan must render")
        .expect("a non-empty plan must produce a script")
}

fn line_index(script: &str, predicate: impl Fn(&str) -> bool) -> usize {
    script
        .lines()
        .position(predicate)
        .unwrap_or_else(|| panic!("expected line not found in script:\n{script}"))
}

/// Production teardown must not turn tool, permission, or resource failures
/// into proof. The former rendering appended `2>/dev/null || true` to every
/// delete and skipped IPv6 when `ip6tables` was absent, so this static contract
/// deliberately fails against that shape. Independent family attempts still
/// fail the script overall when any family is unproven.
#[test]
fn teardown_is_strict_for_both_families_and_verifies_exact_absence() {
    let script = node_waypoint_udp_steer_teardown_script();

    assert!(script.starts_with("set -e\n"), "{script}");
    assert!(
        !script.contains("|| true"),
        "no teardown error may be swallowed:\n{script}"
    );
    assert!(
        !script.contains("if command -v ip6tables"),
        "IPv6 predecessor state must never be silently skipped:\n{script}"
    );
    assert!(
        script.contains("command -v ip6tables")
            && script.contains("ferrum_delete_xtables_rule iptables mangle")
            && script.contains("ferrum_delete_xtables_rule ip6tables mangle"),
        "both families must still be attempted and named exactly:\n{script}"
    );
    assert!(
        script.contains("ferrum_overall=0") && script.contains("exit \"$ferrum_overall\""),
        "a family failure must keep the overall script nonzero:\n{script}"
    );
    assert_family_status_is_captured_outside_conditional_context(&script);
    assert!(
        script.contains("jump remains after deletion")
            && script.contains("chain remains after deletion")
            && script.contains("rule remains after deletion")
            && script.contains("route remains after deletion"),
        "every Ferrum-owned object type needs post-delete absence verification:\n{script}"
    );

    let mark_jump = line_index(&script, |line| {
        line.contains("ferrum_delete_xtables_rule iptables mangle")
    });
    let notrack_jump = line_index(&script, |line| {
        line.contains("ferrum_delete_xtables_rule iptables raw")
    });
    let routing = line_index(&script, |line| line.contains("ip -o rule show priority"));
    assert!(
        mark_jump < notrack_jump && notrack_jump < routing,
        "teardown must stop mark, then notrack, then routing:\n{script}"
    );
}

fn teardown_family_block<'a>(script: &'a str, family: &str) -> &'a str {
    let marker = format!("# NodeWaypoint UDP steer teardown: {family}");
    let start = script
        .find(&marker)
        .unwrap_or_else(|| panic!("missing {family} teardown block:\n{script}"));
    let after = start + marker.len();
    let end = if family == "IPv4" {
        script[after..]
            .find("# NodeWaypoint UDP steer teardown: IPv6")
            .map(|rel| after + rel)
            .unwrap_or_else(|| {
                panic!("IPv4 attempt must end before the IPv6 attempt starts:\n{script}")
            })
    } else {
        script[after..]
            .find("\nexit \"$ferrum_overall\"")
            .map(|rel| after + rel)
            .unwrap_or_else(|| {
                panic!("IPv6 attempt must capture status before the overall exit:\n{script}")
            })
    };
    script[start..end].trim_end()
}

/// `( set -e; ... ) || ferrum_overall=$?` is a conditional context: Bash and
/// dash disable errexit for commands inside that subshell, so an xtables
/// failure can fall through into routing and a later success can wipe the
/// status. The rendered shape must keep the family body as a simple subshell
/// whose `$?` is captured on the next line.
fn assert_family_status_is_captured_outside_conditional_context(script: &str) {
    assert!(
        !script.contains(") || ferrum_overall")
            && !script.contains(") && ferrum_overall")
            && !script.contains("if (\n"),
        "a family subshell in if/&&/|| disables errexit even after inner set -e:\n{script}"
    );
    assert_eq!(
        script.matches("set +e\n(\nset -e\n").count(),
        2,
        "each family must disable outer errexit immediately before a simple subshell that re-enables it:\n{script}"
    );
    assert_eq!(
        script
            .matches(")\nferrum_family_status=$?\nset -e\n")
            .count(),
        2,
        "each family status must be captured on the next line, then outer errexit restored:\n{script}"
    );
    assert_eq!(
        script
            .matches("if [ \"$ferrum_family_status\" -ne 0 ]; then")
            .count(),
        2,
        "each family must accumulate a nonzero status without resetting overall on success:\n{script}"
    );
}

/// A missing or broken IPv6 tool must not prevent the IPv4 cleanup attempt, and
/// an IPv4 failure must not prevent the IPv6 attempt. Overall success still
/// requires both families to be proven, so the script cannot claim `reaped`.
#[test]
fn teardown_attempts_each_family_independently_and_stays_unproven_on_either_failure() {
    let script = node_waypoint_udp_steer_teardown_script();
    let v4 = teardown_family_block(&script, "IPv4");
    let v6 = teardown_family_block(&script, "IPv6");

    let v4_at = script
        .find("# NodeWaypoint UDP steer teardown: IPv4")
        .expect("IPv4 attempt marker");
    let v4_status_at = script[v4_at..]
        .find("ferrum_family_status=$?")
        .map(|rel| v4_at + rel)
        .expect("IPv4 status capture");
    let v6_at = script
        .find("# NodeWaypoint UDP steer teardown: IPv6")
        .expect("IPv6 attempt marker");
    assert!(
        v4_at < v4_status_at && v4_status_at < v6_at,
        "IPv4 status must be captured before the IPv6 attempt starts:\n{script}"
    );

    let helpers_end = script
        .find("\nferrum_overall=0")
        .expect("overall status must start at 0");
    assert!(
        !script[..helpers_end].contains("command -v iptables")
            && !script[..helpers_end].contains("command -v ip6tables")
            && !script[..helpers_end].contains("command -v ip "),
        "a global BOTH-tools preflight would block every family:\n{}",
        &script[..helpers_end]
    );
    assert!(
        !v4.contains("ip6tables") && !v4.contains("ip -6"),
        "missing IPv6 must not gate the IPv4 attempt:\n{v4}"
    );
    assert!(
        v4.contains("command -v iptables >/dev/null 2>&1 || {")
            && v4.contains("ferrum_delete_xtables_rule iptables mangle")
            && v4.contains("set +e")
            && v4.contains("set -e")
            && v4.contains("ferrum_family_status=$?"),
        "the IPv4 attempt must still require iptables and capture status outside a conditional context:\n{v4}"
    );
    assert!(
        !v6.contains("ferrum_delete_xtables_rule iptables mangle")
            && !v6.contains("ip -o rule show")
            && v6.contains("command -v ip6tables >/dev/null 2>&1 || {")
            && v6.contains("ferrum_delete_xtables_rule ip6tables mangle")
            && v6.contains("set +e")
            && v6.contains("set -e")
            && v6.contains("ferrum_family_status=$?"),
        "IPv4 failure must not gate the IPv6 attempt:\n{v6}"
    );
    assert!(
        v4.contains("iptables is required to reap NodeWaypoint UDP steering")
            && v6.contains("ip6tables is required to reap NodeWaypoint UDP steering")
            && script.contains("exit \"$ferrum_overall\""),
        "a missing family tool is a failure of that attempt, and of the script:\n{script}"
    );
    assert_family_status_is_captured_outside_conditional_context(&script);
}

/// Exact Ferrum fwmark ownership is preserved on teardown, and local routing
/// is not removed unless that family's mark path was proven. Inert leftover
/// routing is safer than marked traffic without local delivery.
#[test]
fn teardown_retains_routing_when_the_family_mark_path_is_unproven() {
    let script = node_waypoint_udp_steer_teardown_script();
    let exact = "priority 102 fwmark 0x736/0xffffffff lookup 33136";
    for family in ["IPv4", "IPv6"] {
        let block = teardown_family_block(&script, family);
        let tool = if family == "IPv6" {
            "ip6tables"
        } else {
            "iptables"
        };
        let tool_guard = line_index(block, |line| {
            line.contains(&format!("command -v {tool} >/dev/null 2>&1 || {{"))
        });
        let mark = line_index(block, |line| {
            line.contains(&format!("ferrum_delete_xtables_rule {tool} mangle"))
        });
        let notrack = line_index(block, |line| {
            line.contains(&format!("ferrum_delete_xtables_rule {tool} raw"))
        });
        let ip_guard = line_index(block, |line| {
            line.contains("command -v ip >/dev/null 2>&1 || {")
        });
        let routing = line_index(block, |line| line.contains("rule show priority"));
        assert!(
            tool_guard < mark && mark < notrack && notrack < ip_guard && ip_guard < routing,
            "{family} must prove mark then notrack before considering routing:\n{block}"
        );
        assert!(
            block.contains(exact),
            "{family} routing delete must name Ferrum's exact mark/mask/table:\n{block}"
        );
        assert!(
            !block.contains("rule del priority 102 lookup 33136")
                && !block.contains("rule flush")
                && !block.contains("route flush")
                && !block.contains("ip rule del lookup"),
            "{family} must not delete by priority/table alone or flush:\n{block}"
        );
        assert!(
            !block.contains("fwmark 0x733")
                && !block.contains("fwmark 0x734")
                && !block.contains("fwmark 0x735"),
            "{family} must not match a different mark at the same priority/table:\n{block}"
        );
        assert!(
            block.contains("set +e")
                && block.contains("set -e")
                && block.contains("ferrum_family_status=$?")
                && !block.contains(") || ")
                && !block.contains(") && ")
                && !block.contains("if ("),
            "{family} must fail-fast in a simple subshell and capture status on the next line:\n{block}"
        );
    }
}

/// `( set -e; ... ) || ferrum_overall=$?` continues into IPv4 routing after an
/// xtables failure, and a later successful command can make that subshell
/// return 0. The rendered script must skip IPv4 routing, still attempt IPv6,
/// and exit nonzero. Exercised under Bash (the shell with the documented
/// suppression) and `sh` (the production `sh -c` path).
#[cfg(unix)]
#[test]
fn teardown_ipv4_xtables_failure_skips_ipv4_routing_and_still_attempts_ipv6() {
    let script = node_waypoint_udp_steer_teardown_script();
    // Use absolute shell paths because the child PATH is intentionally limited
    // to the stub tool directory below.
    for shell in ["/bin/bash", "/bin/sh"] {
        let (status, log) = run_teardown_with_stubbed_family_tools(shell, &script);
        assert_ne!(
            status, 0,
            "{shell}: IPv4 xtables failure must keep overall teardown unproven\n{log}"
        );

        let mut saw_iptables = false;
        let mut saw_ip6tables = false;
        let mut ipv4_routing = Vec::new();
        let mut ipv6_routing = Vec::new();
        for line in log.lines() {
            if line == "iptables" || line.starts_with("iptables ") {
                saw_iptables = true;
            } else if line == "ip6tables" || line.starts_with("ip6tables ") {
                saw_ip6tables = true;
            } else if let Some(rest) = line.strip_prefix("ip ") {
                if rest == "-6" || rest.starts_with("-6 ") {
                    ipv6_routing.push(line);
                } else {
                    ipv4_routing.push(line);
                }
            }
        }
        assert!(
            saw_iptables,
            "{shell}: IPv4 xtables must run so the failure is a real inspection error:\n{log}"
        );
        assert!(
            ipv4_routing.is_empty(),
            "{shell}: an IPv4 xtables failure must not reach IPv4 routing: {ipv4_routing:?}\n{log}"
        );
        assert!(
            saw_ip6tables,
            "{shell}: IPv6 must still be attempted after the IPv4 failure:\n{log}"
        );
        assert!(
            !ipv6_routing.is_empty(),
            "{shell}: a proven IPv6 xtables path must still consider IPv6 routing:\n{log}"
        );
    }
}

#[cfg(unix)]
fn run_teardown_with_stubbed_family_tools(shell: &str, script: &str) -> (i32, String) {
    let dir = tempfile::tempdir().expect("stub bin dir");
    let log_path = dir.path().join("stub.log");
    write_exec(
        &dir.path().join("iptables"),
        concat!(
            "#!/bin/sh\n",
            "log=\"${FERRUM_STEER_STUB_LOG:?}\"\n",
            "printf 'iptables' >>\"$log\"\n",
            "for arg in \"$@\"; do printf ' %s' \"$arg\" >>\"$log\"; done\n",
            "printf '\\n' >>\"$log\"\n",
            "exit 2\n"
        ),
    );
    write_exec(
        &dir.path().join("ip6tables"),
        concat!(
            "#!/bin/sh\n",
            "log=\"${FERRUM_STEER_STUB_LOG:?}\"\n",
            "printf 'ip6tables' >>\"$log\"\n",
            "for arg in \"$@\"; do printf ' %s' \"$arg\" >>\"$log\"; done\n",
            "printf '\\n' >>\"$log\"\n",
            "for arg in \"$@\"; do\n",
            "  if [ \"$arg\" = \"-S\" ] || [ \"$arg\" = \"-C\" ]; then exit 1; fi\n",
            "done\n",
            "exit 0\n"
        ),
    );
    write_exec(
        &dir.path().join("ip"),
        concat!(
            "#!/bin/sh\n",
            "log=\"${FERRUM_STEER_STUB_LOG:?}\"\n",
            "printf 'ip' >>\"$log\"\n",
            "for arg in \"$@\"; do printf ' %s' \"$arg\" >>\"$log\"; done\n",
            "printf '\\n' >>\"$log\"\n",
            "exit 0\n"
        ),
    );

    let output = std::process::Command::new(shell)
        .arg("-c")
        .arg(script)
        .env("PATH", dir.path())
        .env("FERRUM_STEER_STUB_LOG", &log_path)
        .output()
        .unwrap_or_else(|error| panic!("failed to exec {shell}: {error}"));
    let log = std::fs::read_to_string(&log_path).unwrap_or_default();
    let status = output.status.code().unwrap_or_else(|| {
        panic!(
            "{shell} was terminated by a signal; stderr={}\n{log}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (status, log)
}

#[cfg(unix)]
fn write_exec(path: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, body).expect("write stub binary");
    let mut permissions = std::fs::metadata(path)
        .expect("stat stub binary")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions).expect("chmod stub binary");
}

/// Issue #2084 / NodeWaypoint UDP Service steering: nft-backed iptables
/// returns 2 for `-C PREROUTING ... -j <missing-user-chain>`, which is not
/// the portable "absent" status 1. Teardown must establish the jump target
/// chain with `-S` first and must not reclassify status 2 as success.
#[test]
fn teardown_probes_jump_target_chain_before_rule_check() {
    let script = node_waypoint_udp_steer_teardown_script();
    let helper = xtables_rule_helper(&script);
    let jump_probe = jump_target_probe_block(helper);

    let chain_probe = helper
        .find("-S \"$ferrum_jump_target\"")
        .expect("jump-target chain existence must be probed with -S");
    let rule_check = helper
        .find("-C \"$@\"")
        .expect("the jump itself is still checked with -C when the chain exists");
    assert!(
        chain_probe < rule_check,
        "chain existence must be established before the jump probe:\n{helper}"
    );
    assert!(
        script.contains("jump-target chain inspection failed")
            && script.contains("rule inspection failed")
            && jump_probe.contains("[ \"$ferrum_status\" -ne 1 ]"),
        "absent chains stay success via -S status 1; other statuses stay fail-closed:\n{jump_probe}"
    );
    assert!(
        !script.contains("[ \"$ferrum_status\" -eq 2 ]")
            && !script.contains("-eq 1 -o")
            && !script.contains("-eq 1] || [ \"$ferrum_status\" -eq 2"),
        "status 2 must not be reclassified as absence:\n{script}"
    );

    assert_no_bang_inverted_status_capture(&script);
    assert_jump_target_probe_retains_original_status(jump_probe);
    assert!(
        helper[rule_check..].contains("-D \"$@\""),
        "a present jump-target chain must still delete via -C/-D:\n{helper}"
    );
}

fn xtables_rule_helper(script: &str) -> &str {
    let start = script
        .find("ferrum_delete_xtables_rule() {")
        .expect("xtables rule helper must be rendered");
    let rest = &script[start..];
    let end = rest
        .find("ferrum_delete_xtables_chain() {")
        .expect("xtables chain helper must follow the rule helper");
    rest[..end].trim_end()
}

fn jump_target_probe_block(helper: &str) -> &str {
    let start = helper
        .find("if [ -n \"$ferrum_jump_target\" ]")
        .expect("jump-target presence must gate the -S probe");
    let rest = &helper[start..];
    let end = rest
        .find("-C \"$@\"")
        .expect("successful -S must fall through to -C");
    &rest[..end]
}

/// POSIX `if ! cmd; then status=$?` records the inverted compound status (0),
/// not `cmd`'s status. Status capture must happen in an `else` (or an
/// uninverted `||`) so lock/permission/resource failures stay fail-closed.
fn assert_no_bang_inverted_status_capture(script: &str) {
    let lines: Vec<&str> = script.lines().map(str::trim).collect();
    for (index, line) in lines.iter().enumerate() {
        if !line.starts_with("if !") {
            continue;
        }
        assert!(
            !line.contains("ferrum_status=$?") && !line.contains("status=$?"),
            "POSIX `if ! cmd; then status=$?` captures 0, not cmd:\n{script}"
        );
        let mut in_then = line.contains("then");
        for follow in &lines[index + 1..] {
            if !in_then {
                if *follow == "then" || follow.starts_with("then ") {
                    in_then = true;
                }
                continue;
            }
            if follow.starts_with("else") || *follow == "fi" || follow.starts_with("fi ") {
                break;
            }
            assert!(
                !follow.contains("ferrum_status=$?") && !follow.contains("status=$?"),
                "POSIX `if ! cmd; then status=$?` captures 0, not cmd:\n{script}"
            );
        }
    }
}

fn assert_jump_target_probe_retains_original_status(jump_probe: &str) {
    assert!(
        !jump_probe.contains("if !"),
        "the -S probe must not invert the iptables status:\n{jump_probe}"
    );
    assert!(
        jump_probe
            .contains("if \"$ferrum_binary\" -t \"$ferrum_table\" -w 5 -S \"$ferrum_jump_target\""),
        "the -S probe must be the non-inverted if-condition:\n{jump_probe}"
    );

    let then_at = jump_probe
        .find("; then")
        .expect("the -S probe must be an if-condition");
    // Skip the outer `if [ -n ... ]; then` and require the inner -S then/else.
    let inner = &jump_probe[then_at + "; then".len()..];
    let inner_then_at = inner
        .find("; then")
        .expect("inner -S if must keep then/else status capture");
    let capture = inner[inner_then_at + "; then".len()..].trim_start();
    assert!(
        capture.starts_with("ferrum_status=0"),
        "successful -S must record status 0 before falling through to -C:\n{jump_probe}"
    );
    let else_at = capture
        .find("else")
        .expect("failed -S must capture status in else");
    let else_body = capture[else_at + "else".len()..].trim_start();
    assert!(
        else_body.starts_with("ferrum_status=$?"),
        "failed -S must retain the original iptables status in else:\n{jump_probe}"
    );
    assert!(
        else_body.contains("[ \"$ferrum_status\" -ne 1 ]")
            && else_body.contains("return \"$ferrum_status\"")
            && else_body.contains("return 0"),
        "status 1 is the only absent-chain success; other nonzeros fail closed:\n{jump_probe}"
    );
    assert!(
        !capture[..else_at].contains("return"),
        "successful -S must fall through to -C/-D, not return:\n{jump_probe}"
    );
}

/// POSIX `case` glob (`*` any sequence, `?` any byte). Used to evaluate the
/// rendered teardown arms the same way `sh` will, without executing the script.
fn posix_case_glob(text: &str, pattern: &str) -> bool {
    fn rec(text: &[u8], pattern: &[u8]) -> bool {
        let Some((&pc, prest)) = pattern.split_first() else {
            return text.is_empty();
        };
        if pc == b'*' {
            if rec(text, prest) {
                return true;
            }
            let Some((_, trest)) = text.split_first() else {
                return false;
            };
            return rec(trest, pattern);
        }
        let Some((&tc, trest)) = text.split_first() else {
            return false;
        };
        (pc == b'?' || pc == tc) && rec(trest, prest)
    }
    rec(text.as_bytes(), pattern.as_bytes())
}

fn posix_case_any(text: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| posix_case_glob(text, pattern))
}

/// Unquote one POSIX `case` alternative (`*'local default dev lo'*` →
/// `*local default dev lo*`) so the glob can be evaluated against `ip route show`
/// fixtures.
fn unquote_case_pattern(raw: &str) -> String {
    raw.replace('\'', "")
}

fn parse_case_globs(pattern_line: &str) -> Vec<String> {
    let trimmed = pattern_line.trim();
    let trimmed = trimmed
        .strip_suffix(')')
        .unwrap_or_else(|| panic!("case arm must close with `)`: {pattern_line}"));
    trimmed
        .split('|')
        .map(|alt| unquote_case_pattern(alt.trim()))
        .filter(|pattern| !pattern.is_empty())
        .collect()
}

struct FamilyRouteTeardown {
    inspect_globs: Vec<String>,
    verify_globs: Vec<String>,
}

fn case_globs_after_show(script: &str, show_at: usize) -> Vec<String> {
    let rest = &script[show_at..];
    let case_at = rest
        .find("case \"$ferrum_route_state\" in")
        .unwrap_or_else(|| panic!("route inspect/verify case missing after show:\n{rest}"));
    let pattern_line = rest[case_at..]
        .lines()
        .nth(1)
        .unwrap_or_else(|| panic!("case pattern line missing after show:\n{rest}"));
    parse_case_globs(pattern_line)
}

fn parse_family_route_teardown(script: &str, ipv6: bool) -> FamilyRouteTeardown {
    let show_helper = if ipv6 {
        "ferrum_show_steer_local_routes 6"
    } else {
        "ferrum_show_steer_local_routes 4"
    };
    let delete_cmd = if ipv6 {
        "ip -6 route del local ::/0 dev lo table 33136"
    } else {
        "ip route del local 0.0.0.0/0 dev lo table 33136"
    };

    let mut positions = Vec::new();
    let mut search_from = 0;
    while let Some(rel) = script[search_from..].find(show_helper) {
        let at = search_from + rel;
        positions.push(at);
        search_from = at + show_helper.len();
    }
    assert_eq!(
        positions.len(),
        2,
        "inspect and verify must each show this family's table once:\n{script}"
    );

    let between = &script[positions[0]..positions[1]];
    assert!(
        between.contains(delete_cmd),
        "delete must follow inspect and use the Ferrum add spelling `{delete_cmd}`:\n{between}"
    );
    assert!(
        !script[positions[1]..].contains(delete_cmd),
        "verify must not issue a second delete:\n{}",
        &script[positions[1]..]
    );

    FamilyRouteTeardown {
        inspect_globs: case_globs_after_show(script, positions[0]),
        verify_globs: case_globs_after_show(script, positions[1]),
    }
}

/// The regression this exists for: iproute2 commonly renders the Ferrum-owned
/// zero-prefix as `local default dev lo …` rather than `local 0.0.0.0/0` /
/// `local ::/0`. Matching only the CIDR form skipped deletion and then skipped
/// the post-delete check, so teardown returned success while the route remained.
/// This evaluates the rendered `case` arms against live and absent dumps — it
/// is not a substring hunt for the word `default`.
#[test]
fn teardown_matches_both_iproute2_spellings_of_the_owned_local_default() {
    let script = node_waypoint_udp_steer_teardown_script();
    let v4 = parse_family_route_teardown(&script, false);
    let v6 = parse_family_route_teardown(&script, true);

    assert_eq!(
        v4.inspect_globs, v4.verify_globs,
        "inspect/verify glob drift would false-succeed on a still-live route:\n{script}"
    );
    assert_eq!(
        v6.inspect_globs, v6.verify_globs,
        "inspect/verify glob drift would false-succeed on a still-live route:\n{script}"
    );
    assert!(
        v4.inspect_globs
            .iter()
            .any(|glob| glob.contains("0.0.0.0/0"))
            && v4
                .inspect_globs
                .iter()
                .any(|glob| glob.contains("local default dev lo")),
        "IPv4 must accept both CIDR and `default` spellings: {:?}",
        v4.inspect_globs
    );
    assert!(
        v6.inspect_globs.iter().any(|glob| glob.contains("::/0"))
            && v6
                .inspect_globs
                .iter()
                .any(|glob| glob.contains("local default dev lo")),
        "IPv6 must accept both CIDR and `default` spellings: {:?}",
        v6.inspect_globs
    );

    let leftover_v4 =
        "local 127.0.0.1 dev lo proto kernel scope host\nlocal 10.96.0.10 dev lo scope host";
    let leftover_v6 =
        "local ::1 dev lo proto kernel metric 1024 pref medium\nlocal fd00::10 dev lo metric 1024";
    let default_v4 = "local default dev lo proto kernel scope host";
    let cidr_v4 = "local 0.0.0.0/0 dev lo proto kernel scope host";
    let default_v6 = "local default dev lo proto kernel metric 1024 pref medium";
    let cidr_v6 = "local ::/0 dev lo proto kernel metric 1024 pref medium";

    for dump in [
        default_v4,
        cidr_v4,
        &format!("{leftover_v4}\n{default_v4}"),
        &format!("{leftover_v4}\n{cidr_v4}"),
    ] {
        assert!(
            posix_case_any(dump, &v4.inspect_globs),
            "IPv4 live Ferrum route must match and be deleted:\n{dump}\n{:?}",
            v4.inspect_globs
        );
        assert!(
            posix_case_any(dump, &v4.verify_globs),
            "IPv4 live Ferrum route must fail the post-delete check:\n{dump}"
        );
    }
    for dump in [
        default_v6,
        cidr_v6,
        &format!("{leftover_v6}\n{default_v6}"),
        &format!("{leftover_v6}\n{cidr_v6}"),
    ] {
        assert!(
            posix_case_any(dump, &v6.inspect_globs),
            "IPv6 live Ferrum route must match and be deleted:\n{dump}\n{:?}",
            v6.inspect_globs
        );
        assert!(
            posix_case_any(dump, &v6.verify_globs),
            "IPv6 live Ferrum route must fail the post-delete check:\n{dump}"
        );
    }

    for dump in [
        "",
        leftover_v4,
        "local default dev eth0 scope host",
        cidr_v6,
    ] {
        assert!(
            !posix_case_any(dump, &v4.inspect_globs),
            "IPv4 must treat this as absence / not-ours and not delete:\n{dump}"
        );
        assert!(
            !posix_case_any(dump, &v4.verify_globs),
            "IPv4 post-delete check must succeed for absence / not-ours:\n{dump}"
        );
    }
    for dump in [
        "",
        leftover_v6,
        "local default dev eth0 metric 1024",
        cidr_v4,
    ] {
        assert!(
            !posix_case_any(dump, &v6.inspect_globs),
            "IPv6 must treat this as absence / not-ours and not delete:\n{dump}"
        );
        assert!(
            !posix_case_any(dump, &v6.verify_globs),
            "IPv6 post-delete check must succeed for absence / not-ours:\n{dump}"
        );
    }

    let v4_rule = line_index(&script, |line| {
        line.contains("ip -o rule show priority") && !line.contains("ip -6")
    });
    let v4_route = line_index(&script, |line| {
        line.contains("ip route del local 0.0.0.0/0 dev lo table 33136")
    });
    let v6_rule = line_index(&script, |line| line.contains("ip -6 -o rule show priority"));
    let v6_route = line_index(&script, |line| {
        line.contains("ip -6 route del local ::/0 dev lo table 33136")
    });
    assert!(
        v4_rule < v4_route && v6_rule < v6_route,
        "each family must delete the policy rule before the local route:\n{script}"
    );
}

fn steer_local_routes_helper(script: &str) -> &str {
    let start = script
        .find("ferrum_show_steer_local_routes() {")
        .expect("route-show helper must be rendered");
    let rest = &script[start..];
    let end = rest
        .find("\nferrum_overall=")
        .expect("independent family attempts must follow the route-show helper");
    rest[..end].trim_end()
}

fn fib_absence_globs(helper: &str) -> Vec<String> {
    let case_at = helper
        .find("case \"$ferrum_show\" in")
        .expect("missing-table classification must case on the captured show output");
    let pattern_line = helper[case_at..]
        .lines()
        .nth(1)
        .unwrap_or_else(|| panic!("FIB-absence case pattern missing:\n{helper}"));
    parse_case_globs(pattern_line)
}

/// Hosted NodeWaypoint UDP Service-path failure: first-pass teardown ran
/// `ip route show table 33136 type local` under `set -e` while the Ferrum FIB
/// table had never been created. iproute2 exits 2 with
/// `Error: ipv4: FIB table does not exist.` / `Dump terminated`, so teardown
/// never proved absence, `reaped` stayed false, setup never ran, kube-proxy
/// DNATed ClusterIP traffic, and the pod-veth guard dropped it
/// (`backend_hits=0`). Direct listener probes still passed because they do
/// not need steering. Missing-table is genuine absence; other show failures
/// stay fail-closed. The same dump happens after the last local route is
/// deleted, so inspect AND verify must share the helper.
#[test]
fn teardown_treats_a_missing_fib_table_as_genuine_absence() {
    let script = node_waypoint_udp_steer_teardown_script();
    let helper = steer_local_routes_helper(&script);

    assert!(
        helper.contains("ip route show table 33136 type local 2>&1")
            && helper.contains("ip -6 route show table 33136 type local 2>&1"),
        "both families must inspect the Ferrum table and keep stderr for classification:\n{helper}"
    );
    assert!(
        !helper.contains("2>/dev/null"),
        "swallowing stderr would lose the missing-table diagnostic:\n{helper}"
    );
    assert!(
        helper.contains("|| ferrum_status=$?")
            && helper.contains("*'FIB table does not exist'*")
            && helper.contains("ferrum_route_state=\"\"")
            && helper.contains("return 0"),
        "the hosted iproute2 missing-table dump must classify as empty absence:\n{helper}"
    );
    assert!(
        helper.contains("route inspection failed") && helper.contains("return \"$ferrum_status\""),
        "permission and other show failures must keep their original status:\n{helper}"
    );
    assert!(
        !helper.contains("[ \"$ferrum_status\" -eq 2 ]") && !helper.contains("|| true"),
        "exit 2 is not absence by itself; only the FIB-missing diagnostic is:\n{helper}"
    );
    assert_no_bang_inverted_status_capture(helper);

    assert_eq!(
        script.matches("ferrum_show_steer_local_routes 4").count(),
        2,
        "IPv4 inspect and post-delete verify must share the helper:\n{script}"
    );
    assert_eq!(
        script.matches("ferrum_show_steer_local_routes 6").count(),
        2,
        "IPv6 inspect and post-delete verify must share the helper:\n{script}"
    );

    let absence_globs = fib_absence_globs(helper);
    for dump in [
        "Error: ipv4: FIB table does not exist.\nDump terminated",
        "Error: ipv6: FIB table does not exist.\nDump terminated",
        "Error: ipv4: FIB table does not exist.",
    ] {
        assert!(
            posix_case_any(dump, &absence_globs),
            "missing-table dump must classify as absence:\n{dump}\n{absence_globs:?}"
        );
    }
    for dump in [
        "RTNETLINK answers: Operation not permitted",
        "Error: Failed to send dump request: Operation not permitted",
        "Dump terminated",
        "local default dev lo proto kernel scope host",
    ] {
        assert!(
            !posix_case_any(dump, &absence_globs),
            "non-absence dump must stay a show failure:\n{dump}\n{absence_globs:?}"
        );
    }
}

/// The update-order contract (issue #3286 root review). During a generation
/// change the OLD mangle mark rules must stop matching BEFORE the raw notrack
/// chain is repopulated. Otherwise a datagram to an old-generation destination
/// is still marked while its conntrack exemption is already gone: `nat
/// PREROUTING` DNATs it to a backing pod and the surviving mark then delivers
/// THAT rewritten datagram locally — cross-generation, wrong-destination
/// admission. A brief unsteered (fail-closed) window is the acceptable trade.
#[test]
fn marking_stops_before_the_notrack_prerequisites_are_replaced() {
    let script = setup_script(&["veth0"], &[destination("10.96.0.10", 5300)]);

    let mangle_flush = line_index(&script, |line| {
        line.contains("-t mangle") && line.contains("-F FERRUM_NW_UDP_STEER")
    });
    let raw_flush = line_index(&script, |line| {
        line.contains("-t raw") && line.contains("-F FERRUM_NW_UDP_NOTRACK")
    });
    let notrack_rule = line_index(&script, |line| line.contains("-j CT --notrack"));
    let mark_rule = line_index(&script, |line| line.contains("-j MARK --set-xmark"));
    let mangle_jump = line_index(&script, |line| {
        line.contains("-t mangle") && line.contains("-A PREROUTING -p udp -j FERRUM_NW_UDP_STEER")
    });

    assert!(
        mangle_flush < raw_flush,
        "the mark chain must be emptied before the notrack chain is flushed:\n{script}"
    );
    assert!(
        notrack_rule < mark_rule,
        "every destination's conntrack exemption must precede its mark rule:\n{script}"
    );
    assert!(
        mark_rule < mangle_jump,
        "the mark rules must exist before the mangle jump makes them observable:\n{script}"
    );
}

/// Local delivery must exist before anything can be marked: a mark with no
/// `fwmark` rule and no `local` route is a black hole rather than a steer.
#[test]
fn local_delivery_routing_precedes_every_mark_rule() {
    let script = setup_script(&["veth0"], &[destination("10.96.0.10", 5300)]);
    let rule_add = line_index(&script, |line| line.contains("ip rule add priority"));
    let route_add = line_index(&script, |line| line.contains("route add local 0.0.0.0/0"));
    let mark_rule = line_index(&script, |line| line.contains("-j MARK --set-xmark"));
    assert!(rule_add < mark_rule && route_add < mark_rule, "\n{script}");
}

/// Delete-before-add must name Ferrum's exact fwmark selector. A
/// priority/table-only delete would also remove a co-resident policy rule at
/// 102/33136 whose mark is not 0x736/0xffffffff.
#[test]
fn setup_delete_before_add_owns_only_the_ferrum_fwmark_rule() {
    let v4 = setup_script(&["veth0"], &[destination("10.96.0.10", 5300)]);
    let v6 = setup_script(&["veth0"], &[destination("fd00::10", 5300)]);
    let both = setup_script(
        &["veth0"],
        &[
            destination("10.96.0.10", 5300),
            destination("fd00::10", 5300),
        ],
    );
    let ferrum = "priority 102 fwmark 0x736/0xffffffff lookup 33136";
    let foreign_same_pri_table = "priority 102 fwmark 0x733/0xffffffff lookup 33136";

    for (label, script, del, add) in [
        (
            "IPv4",
            v4.as_str(),
            "ip rule del priority 102 fwmark 0x736/0xffffffff lookup 33136",
            "ip rule add priority 102 fwmark 0x736/0xffffffff lookup 33136",
        ),
        (
            "IPv6",
            v6.as_str(),
            "ip -6 rule del priority 102 fwmark 0x736/0xffffffff lookup 33136",
            "ip -6 rule add priority 102 fwmark 0x736/0xffffffff lookup 33136",
        ),
    ] {
        assert!(
            script.contains(del) && script.contains(add),
            "{label} setup must delete then add Ferrum's exact selector:\n{script}"
        );
        let del_at = line_index(script, |line| line.contains(del));
        let add_at = line_index(script, |line| line.contains(add));
        assert!(
            del_at < add_at,
            "{label} exact delete must precede the load-bearing add:\n{script}"
        );
        for line in script.lines().filter(|line| line.contains("rule del")) {
            assert!(
                line.contains(ferrum),
                "{label} delete-before-add must carry the exact mark/mask: {line}"
            );
            assert!(
                !line.contains("rule del priority 102 lookup 33136")
                    && !line.contains("rule flush")
                    && !line.contains("ip rule del lookup"),
                "{label} must not delete by priority/table alone: {line}"
            );
            assert!(
                !line.contains(foreign_same_pri_table) && !line.contains("fwmark 0x733"),
                "{label} rendered delete cannot match a different mark at 102/33136: {line}"
            );
        }
    }

    assert!(
        both.contains("ip rule del priority 102 fwmark 0x736/0xffffffff lookup 33136")
            && both.contains("ip -6 rule del priority 102 fwmark 0x736/0xffffffff lookup 33136")
            && !both.contains("rule del priority 102 lookup 33136")
            && !both.contains("route flush table 33136"),
        "dual-family setup must keep both exact deletes and never flush:\n{both}"
    );
}

/// A published address family is installed COMPLETELY or the apply fails. The
/// earlier shape wrapped the IPv6 half in `if command -v ip6tables; ... else
/// echo ...; fi`, which exits 0 — so a node without `ip6tables` recorded the
/// whole plan as applied and silently black-holed every IPv6 Service datagram,
/// forever, with no retry.
#[test]
fn a_missing_family_binary_fails_the_whole_apply_rather_than_being_skipped() {
    let script = setup_script(
        &["veth0"],
        &[
            destination("10.96.0.10", 5300),
            destination("fd00::10", 5300),
        ],
    );
    assert!(
        script.starts_with("set -e\n"),
        "the script must abort on the first failing command:\n{script}"
    );
    assert!(
        script.contains("command -v ip6tables >/dev/null 2>&1 || {"),
        "a published IPv6 destination must hard-require ip6tables:\n{script}"
    );
    assert!(
        !script.contains("else"),
        "no best-effort arm may survive: a skipped family is a silent black hole:\n{script}"
    );
    assert!(
        script.contains("command -v iptables >/dev/null 2>&1 || {"),
        "the IPv4 family carries the same guard:\n{script}"
    );
}

/// An IPv4-only plan must not require `ip6tables`: only PUBLISHED families are
/// mandatory, so an IPv6-less node keeps working.
#[test]
fn an_ipv4_only_plan_does_not_require_ip6tables() {
    let script = setup_script(&["veth0"], &[destination("10.96.0.10", 5300)]);
    assert!(
        !script.contains("ip6tables"),
        "an unpublished family must emit nothing at all:\n{script}"
    );
}

/// Every rule is scoped by BOTH the ingress interface and the exact Service
/// address+port. Port-only scoping would steer a workload's traffic to an
/// unrelated off-cluster host that happens to share the port number.
#[test]
fn every_rule_is_scoped_by_interface_and_exact_service_address() {
    let script = setup_script(&["veth0"], &[destination("10.96.0.10", 5300)]);
    for line in script
        .lines()
        .filter(|line| line.contains("-j CT --notrack") || line.contains("-j MARK --set-xmark"))
    {
        assert!(line.contains("-i veth0"), "unscoped interface: {line}");
        assert!(
            line.contains("-d 10.96.0.10/32"),
            "unscoped destination: {line}"
        );
        assert!(line.contains("--dport 5300"), "unscoped port: {line}");
    }
}

/// Bound destinations are instance-owned. Setting them applies immediately
/// against the supplied interfaces. Clearing them with `serving == false` is a
/// true withdrawal; an empty destination set with `serving == true` keeps the
/// sender proof live.
#[test]
fn set_bound_destinations_applies_immediately_and_empty_tears_down() {
    let backend = RecordingBackend::new(false);
    let steering = NodeWaypointUdpSteering::new(backend.clone());
    let ifaces = vec!["veth0".to_string()];
    let destinations = vec![destination("10.96.0.10", 5300)];

    assert_eq!(
        steering.set_bound_destinations(destinations.clone(), Some(&ifaces), true),
        SteerReconcileOutcome::Applied
    );
    assert_eq!(steering.bound_destinations(), destinations);
    let first = backend.take();
    assert!(is_teardown(&first[0]));
    assert!(!is_teardown(&first[1]));

    assert_eq!(
        steering.set_bound_destinations(Vec::new(), Some(&ifaces), false),
        SteerReconcileOutcome::Removed
    );
    assert!(steering.bound_destinations().is_empty());
    let second = backend.take();
    assert_eq!(second.len(), 1);
    assert!(is_teardown(&second[0]));
    forget(steering);
}

/// A bind-loss retraction of one port must not keep that destination marked.
#[test]
fn retract_port_drops_only_that_destination() {
    let backend = RecordingBackend::new(false);
    let steering = NodeWaypointUdpSteering::new(backend.clone());
    let ifaces = vec!["veth0".to_string()];
    steering.set_bound_destinations(
        vec![
            destination("10.96.0.10", 5300),
            destination("10.96.0.11", 5301),
        ],
        Some(&ifaces),
        true,
    );
    backend.take();

    assert_eq!(steering.retract_port(5300), SteerReconcileOutcome::Applied);
    assert_eq!(
        steering.bound_destinations(),
        vec![destination("10.96.0.11", 5301)]
    );
    forget(steering);
}

// ── Serialized latest-state machine (issue #3286 exact-head review) ────────

/// Blocks the next non-teardown script so a later event can be queued behind
/// the in-flight reconcile. Destination/interface updates hold the same mutex
/// across the component write and this backend call, so the queued event
/// always observes the latest combined state.
struct ArmedBarrierBackend {
    scripts: Mutex<Vec<String>>,
    arm: Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
}

impl ArmedBarrierBackend {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            scripts: Mutex::new(Vec::new()),
            arm: Mutex::new(None),
        })
    }

    fn arm(&self) -> (Arc<std::sync::Barrier>, Arc<std::sync::Barrier>) {
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        *self.arm.lock().expect("arm lock") = Some((entered.clone(), release.clone()));
        (entered, release)
    }
}

impl NodeWaypointUdpSteerBackend for ArmedBarrierBackend {
    fn run_script(&self, script: &str) -> Result<(), String> {
        self.scripts
            .lock()
            .expect("recording backend lock")
            .push(script.to_string());
        if is_teardown(script) {
            return Ok(());
        }
        if let Some((entered, release)) = self.arm.lock().expect("arm lock").take() {
            entered.wait();
            release.wait();
        }
        Ok(())
    }
}

/// Plan B is in-flight (component stored, backend blocked). Plan C is the
/// later logical event. C must own the installed plan; B must not install
/// after C has already been published.
#[test]
fn later_bound_destination_update_owns_the_installed_plan() {
    let backend = ArmedBarrierBackend::new();
    let steering = Arc::new(NodeWaypointUdpSteering::new(backend.clone()));
    let ifaces = vec!["veth0".to_string()];
    let plan_b = vec![destination("10.96.0.10", 5300)];
    let plan_c = vec![destination("10.96.0.11", 5301)];

    let (entered, release) = backend.arm();
    let steering_b = steering.clone();
    let ifaces_b = ifaces.clone();
    let plan_b_thread = plan_b.clone();
    let handle_b = std::thread::spawn(move || {
        steering_b.set_bound_destinations(plan_b_thread, Some(&ifaces_b), true)
    });
    entered.wait();

    let steering_c = steering.clone();
    let ifaces_c = ifaces.clone();
    let plan_c_thread = plan_c.clone();
    let handle_c = std::thread::spawn(move || {
        steering_c.set_bound_destinations(plan_c_thread, Some(&ifaces_c), true)
    });

    release.wait();
    handle_b.join().expect("plan B thread");
    handle_c.join().expect("plan C thread");

    assert_eq!(
        steering.bound_destinations(),
        plan_c,
        "the later logical event must own the installed plan"
    );
    std::mem::forget(steering);
}

/// A retract that races a later full-plan update must filter the LATEST
/// desired set, not a stale snapshot taken before the full plan was stored.
/// Full plan adds 5302 while 5300+5301 are already applied; retract drops
/// 5300. Legal finals: the full plan (retract ran first) or 5301+5302
/// (retract ran last). `[5301]` alone is the stale-load bug.
#[test]
fn retract_filters_the_latest_desired_set_not_a_stale_snapshot() {
    let backend = ArmedBarrierBackend::new();
    let steering = Arc::new(NodeWaypointUdpSteering::new(backend.clone()));
    let ifaces = vec!["veth0".to_string()];
    let initial = vec![
        destination("10.96.0.10", 5300),
        destination("10.96.0.11", 5301),
    ];
    let full = vec![
        destination("10.96.0.10", 5300),
        destination("10.96.0.11", 5301),
        destination("10.96.0.12", 5302),
    ];
    let retract_after_full = vec![
        destination("10.96.0.11", 5301),
        destination("10.96.0.12", 5302),
    ];

    assert_eq!(
        steering.set_bound_destinations(initial, Some(&ifaces), true),
        SteerReconcileOutcome::Applied
    );

    let (entered, release) = backend.arm();
    let steering_full = steering.clone();
    let ifaces_full = ifaces.clone();
    let full_thread = full.clone();
    let handle_full = std::thread::spawn(move || {
        steering_full.set_bound_destinations(full_thread, Some(&ifaces_full), true)
    });
    entered.wait();

    let steering_retract = steering.clone();
    let handle_retract = std::thread::spawn(move || steering_retract.retract_port(5300));

    release.wait();
    handle_full.join().expect("full-plan thread");
    handle_retract.join().expect("retract thread");

    assert_eq!(
        steering.bound_destinations(),
        retract_after_full,
        "retract queued behind the full plan must drop 5300 from the latest set, keeping 5302"
    );
    std::mem::forget(steering);
}

/// The other retract/full order: retract is in-flight, then the full plan is
/// the later event and must own the installed plan (including 5300).
#[test]
fn later_full_plan_owns_the_installed_plan_over_an_in_flight_retract() {
    let backend = ArmedBarrierBackend::new();
    let steering = Arc::new(NodeWaypointUdpSteering::new(backend.clone()));
    let ifaces = vec!["veth0".to_string()];
    let initial = vec![
        destination("10.96.0.10", 5300),
        destination("10.96.0.11", 5301),
    ];
    let full = vec![
        destination("10.96.0.10", 5300),
        destination("10.96.0.11", 5301),
        destination("10.96.0.12", 5302),
    ];

    assert_eq!(
        steering.set_bound_destinations(initial, Some(&ifaces), true),
        SteerReconcileOutcome::Applied
    );

    let (entered, release) = backend.arm();
    let steering_retract = steering.clone();
    let handle_retract = std::thread::spawn(move || steering_retract.retract_port(5300));
    entered.wait();

    let steering_full = steering.clone();
    let ifaces_full = ifaces.clone();
    let full_thread = full.clone();
    let handle_full = std::thread::spawn(move || {
        steering_full.set_bound_destinations(full_thread, Some(&ifaces_full), true)
    });

    release.wait();
    handle_retract.join().expect("retract thread");
    handle_full.join().expect("full-plan thread");

    assert_eq!(
        steering.bound_destinations(),
        full,
        "the later full-plan event must own the installed plan"
    );
    std::mem::forget(steering);
}

// ── Reply-source authorization lifecycle and acknowledgement (issue #3286) ─
//
// Steering preserves the Service ClusterIP as the datagram's local address, so
// the listener's reply is source-pinned to it — and a ClusterIP is never a
// configured node IP, so `tc_inbound` drops that reply unless the exact
// `(address, port)` pair is authorized. The rules and the authorization are
// therefore two halves of ONE datapath, and the order they move in is the
// contract: authorize before steering, withdraw after un-steering, and tear the
// whole generation down if either half fails.
//
// Crucially, PUBLISHING is not APPLYING. The node-agent owns every BPF map
// write and polls this channel on its own cadence, so a reconcile that
// installed rules on the strength of its own publication would open a
// steered-but-unanswerable window on every generation — and would keep the new
// rules installed indefinitely if the node-agent never converged. These tests
// pin the acknowledgement gate that closes it, against the REAL manifest /
// acknowledgement protocol over a temporary registry directory.

/// Records reply-source publications on the SAME log as the scripts, so
/// ordering between the two halves is observable as one sequence, and models
/// the node-agent by driving the real acknowledgement file.
struct RecordingPublisher {
    inner: RegistryDirReplySourcePublisher,
    registry: std::path::PathBuf,
    log: Arc<Mutex<Vec<String>>>,
    fail_publish: Arc<std::sync::atomic::AtomicBool>,
    fail_read_ack: Arc<std::sync::atomic::AtomicBool>,
    /// Models a node-agent that has already applied the generation by the time
    /// the reconcile looks. Off means the generation stays PENDING until a test
    /// calls [`NodeAgentFake::acknowledge_latest`].
    auto_acknowledge: Arc<std::sync::atomic::AtomicBool>,
}

impl NodeWaypointUdpReplySourcePublisher for RecordingPublisher {
    fn publish(
        &self,
        sources: &[NodeWaypointUdpSteerDestination],
        active: bool,
    ) -> Result<ReplySourceGeneration, String> {
        let entry = if !active {
            "publish:withdraw".to_string()
        } else if sources.is_empty() {
            "publish:active:0".to_string()
        } else {
            format!("publish:{}", sources.len())
        };
        if self.fail_publish.load(std::sync::atomic::Ordering::SeqCst) {
            self.log
                .lock()
                .expect("publisher log")
                .push(format!("{entry}:failed"));
            return Err("injected reply-source publication failure".to_string());
        }
        let generation = self.inner.publish(sources, active)?;
        if self
            .auto_acknowledge
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            write_acknowledgement(&self.registry, &generation).expect("node-agent acknowledgement");
        }
        self.log.lock().expect("publisher log").push(entry);
        Ok(generation)
    }

    fn acknowledged(&self) -> Result<Option<ReplySourceGeneration>, String> {
        if self.fail_read_ack.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("injected acknowledgement read failure".to_string());
        }
        self.inner.acknowledged()
    }
}

/// Runs scripts onto a shared log so publications and scripts interleave.
struct SharedLogBackend {
    log: Arc<Mutex<Vec<String>>>,
    fail_teardown: Arc<std::sync::atomic::AtomicBool>,
}

impl NodeWaypointUdpSteerBackend for SharedLogBackend {
    fn run_script(&self, script: &str) -> Result<(), String> {
        let entry = if is_teardown(script) {
            "script:teardown"
        } else {
            "script:setup"
        };
        self.log
            .lock()
            .expect("backend log")
            .push(entry.to_string());
        if entry == "script:teardown"
            && self.fail_teardown.load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("injected steering teardown failure".to_string());
        }
        Ok(())
    }
}

/// The node-agent's half of the channel, driven explicitly by a test.
struct NodeAgentFake {
    registry: tempfile::TempDir,
    auto_acknowledge: Arc<std::sync::atomic::AtomicBool>,
    fail_publish: Arc<std::sync::atomic::AtomicBool>,
    fail_read_ack: Arc<std::sync::atomic::AtomicBool>,
    fail_teardown: Arc<std::sync::atomic::AtomicBool>,
    log: Arc<Mutex<Vec<String>>>,
}

impl NodeAgentFake {
    /// Apply whatever is published and acknowledge exactly that generation —
    /// the node-agent's success path.
    fn acknowledge_latest(&self) {
        let desired = read_desired_generation(self.registry.path())
            .expect("read desired generation")
            .expect("a generation is published");
        write_acknowledgement(self.registry.path(), &desired.generation)
            .expect("node-agent acknowledgement");
    }

    /// Withdraw the acknowledgement without touching the desired generation —
    /// the node-agent's refusal path (an over-bound set, a missing map, a scan
    /// or insert error), and also what a wiped scratch directory looks like.
    fn withdraw_acknowledgement(&self) {
        clear_acknowledgement(self.registry.path()).expect("clear acknowledgement");
    }

    fn entries(&self) -> Vec<String> {
        self.log.lock().expect("shared log").clone()
    }

    fn take_entries(&self) -> Vec<String> {
        std::mem::take(&mut *self.log.lock().expect("shared log"))
    }
}

fn acknowledged_steering(auto_acknowledge: bool) -> (NodeWaypointUdpSteering, NodeAgentFake) {
    let registry = tempfile::tempdir().expect("registry dir");
    let log = Arc::new(Mutex::new(Vec::new()));
    let auto = Arc::new(std::sync::atomic::AtomicBool::new(auto_acknowledge));
    let fail_publish = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fail_read_ack = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fail_teardown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let publisher = RecordingPublisher {
        inner: RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID)),
        registry: registry.path().to_path_buf(),
        log: log.clone(),
        fail_publish: fail_publish.clone(),
        fail_read_ack: fail_read_ack.clone(),
        auto_acknowledge: auto.clone(),
    };
    let steering = NodeWaypointUdpSteering::new(Arc::new(SharedLogBackend {
        log: log.clone(),
        fail_teardown: fail_teardown.clone(),
    }))
    .with_reply_source_publisher(Arc::new(publisher));
    let agent = NodeAgentFake {
        registry,
        auto_acknowledge: auto,
        fail_publish,
        fail_read_ack,
        fail_teardown,
        log,
    };
    (steering, agent)
}

fn ifaces() -> Vec<String> {
    vec!["veth0".to_string()]
}

/// The apply order. A reply source must be authorized BEFORE the rules that
/// send datagrams at it exist; the reverse order opens a window on every new
/// generation in which a workload's datagram reaches the listener and the
/// listener's reply is dropped by this node's own pod-veth guard.
#[test]
fn a_generation_authorizes_its_reply_sources_before_it_steers_anything() {
    let (steering, agent) = acknowledged_steering(true);

    assert_eq!(
        steering.reconcile_with(
            &ifaces(),
            &[
                destination("10.96.0.10", 5300),
                destination("fd00::a", 5300),
            ],
            true,
        ),
        SteerReconcileOutcome::Applied
    );

    assert_eq!(
        agent.entries(),
        vec![
            // The first pass still reaps a predecessor's rules.
            "script:teardown".to_string(),
            // Then authorize, and only then — once the node-agent has proven
            // both families live — steer.
            "publish:2".to_string(),
            "script:setup".to_string(),
        ],
        "reply sources must be authorized before the steering rules are installed"
    );
    forget(steering);
}

/// The gate this repair exists for. Publishing a claim is a REQUEST; the maps
/// belong to the node-agent. Until it has acknowledged this exact generation no
/// steering rule may exist, or every add/update has a window in which the
/// Service path is steered at a listener whose replies the pod-veth guard drops
/// — and a node-agent that never converges makes that window permanent.
#[test]
fn no_setup_runs_until_the_exact_generation_is_acknowledged() {
    let (steering, agent) = acknowledged_steering(false);
    let destinations = [destination("10.96.0.10", 5300)];

    assert_eq!(
        steering.reconcile_with(&ifaces(), &destinations, true),
        SteerReconcileOutcome::PendingAck,
        "an unacknowledged generation must not install steering rules"
    );
    let pending = agent.take_entries();
    assert!(
        pending.contains(&"publish:1".to_string()),
        "the generation must be published so the node-agent can apply it: {pending:?}"
    );
    assert!(
        !pending.contains(&"script:setup".to_string()),
        "no datagram may be steered before the authorization is proven live: {pending:?}"
    );

    // The node-agent converges. The very next ordinary reconcile installs.
    agent.acknowledge_latest();
    assert_eq!(
        steering.reconcile_with(&ifaces(), &destinations, true),
        SteerReconcileOutcome::Applied
    );
    let applied = agent.take_entries();
    assert!(
        applied.contains(&"script:setup".to_string()),
        "an acknowledged generation must install on the next reconcile: {applied:?}"
    );
    assert!(
        !applied.contains(&"script:teardown".to_string()),
        "the retry must not churn the datapath it already proved absent: {applied:?}"
    );

    // And it settles: no republish, no command.
    assert_eq!(
        steering.reconcile_with(&ifaces(), &destinations, true),
        SteerReconcileOutcome::Unchanged
    );
    assert!(agent.entries().is_empty());
    forget(steering);
}

/// A pending generation must be retried indefinitely WITHOUT walking its
/// sequence forward, or the acknowledgement could never catch up — and without
/// blocking: every pass returns immediately.
#[test]
fn a_pending_generation_is_retried_without_advancing_it() {
    let (steering, agent) = acknowledged_steering(false);
    let destinations = [destination("10.96.0.10", 5300)];

    for _ in 0..4 {
        assert_eq!(
            steering.reconcile_with(&ifaces(), &destinations, true),
            SteerReconcileOutcome::PendingAck
        );
    }
    assert!(
        !agent.entries().contains(&"script:setup".to_string()),
        "no pass may steer while the generation is unproven"
    );

    agent.acknowledge_latest();
    assert_eq!(
        steering.reconcile_with(&ifaces(), &destinations, true),
        SteerReconcileOutcome::Applied,
        "the sequence must not have advanced past the acknowledgement"
    );
    forget(steering);
}

/// An acknowledgement of the PREVIOUS generation is not evidence about this
/// one. A change of the serving set must re-prove itself, and — because the old
/// rules steer at addresses the new generation may not authorize — the existing
/// rules are REVERTED while it does.
#[test]
fn a_stale_acknowledgement_never_satisfies_a_new_generation() {
    let (steering, agent) = acknowledged_steering(false);
    let first = [destination("10.96.0.10", 5300)];
    let second = [destination("10.96.0.11", 5301)];

    steering.reconcile_with(&ifaces(), &first, true);
    agent.acknowledge_latest();
    assert_eq!(
        steering.reconcile_with(&ifaces(), &first, true),
        SteerReconcileOutcome::Applied
    );
    agent.take_entries();

    // The serving set changes; the node-agent has not caught up.
    assert_eq!(
        steering.reconcile_with(&ifaces(), &second, true),
        SteerReconcileOutcome::PendingAck,
        "the previous generation's acknowledgement must not satisfy the new one"
    );
    let pending = agent.take_entries();
    assert_eq!(
        pending,
        vec!["script:teardown".to_string(), "publish:1".to_string()],
        "the outgoing generation's rules must be removed, and no new rule installed"
    );

    agent.acknowledge_latest();
    assert_eq!(
        steering.reconcile_with(&ifaces(), &second, true),
        SteerReconcileOutcome::Applied
    );
    forget(steering);
}

/// An acknowledgement that DISAPPEARS (the node-agent refused the set on a
/// later poll, lost its maps, or restarted without reapplying) must revert the
/// steering rules rather than leave them installed against an unproven
/// authorization.
#[test]
fn a_withdrawn_acknowledgement_reverts_the_installed_steering() {
    let (steering, agent) = acknowledged_steering(true);
    let destinations = [destination("10.96.0.10", 5300)];

    assert_eq!(
        steering.reconcile_with(&ifaces(), &destinations, true),
        SteerReconcileOutcome::Applied
    );
    agent.take_entries();

    // The node-agent retracts its proof; the desired generation is unchanged.
    agent
        .auto_acknowledge
        .store(false, std::sync::atomic::Ordering::SeqCst);
    agent.withdraw_acknowledgement();

    assert_eq!(
        steering.reconcile_with(&ifaces(), &destinations, true),
        SteerReconcileOutcome::PendingAck
    );
    let reverted = agent.take_entries();
    assert!(
        reverted.contains(&"script:teardown".to_string()),
        "an unproven authorization must not keep its steering rules: {reverted:?}"
    );
    assert!(
        !reverted.contains(&"script:setup".to_string()),
        "and must not reinstall them: {reverted:?}"
    );

    agent.acknowledge_latest();
    assert_eq!(
        steering.reconcile_with(&ifaces(), &destinations, true),
        SteerReconcileOutcome::Applied
    );
    forget(steering);
}

/// The teardown order is the mirror image: the rules go first, so nothing is
/// steered at an address whose authorization is about to disappear.
#[test]
fn a_teardown_unsteers_before_it_withdraws_authorization() {
    let (steering, agent) = acknowledged_steering(true);

    assert_eq!(
        steering.reconcile_with(&ifaces(), &[destination("10.96.0.10", 5300)], true),
        SteerReconcileOutcome::Applied
    );
    agent.take_entries();

    // Withdrawing the last destination is the ordinary listener-stop path.
    assert_eq!(
        steering.reconcile_with(&ifaces(), &[], false),
        SteerReconcileOutcome::Removed
    );
    assert_eq!(
        agent.entries(),
        vec![
            "script:teardown".to_string(),
            "publish:withdraw".to_string()
        ],
        "the steering rules must be removed before the authorization they relied on"
    );
    forget(steering);
}

/// "Rules first" means a SUCCESSFUL exact-name teardown, not merely an
/// attempted command. If teardown fails, publishing the empty generation would
/// let the node-agent revoke reply authorization while stale rules still steer
/// traffic, recreating the black hole and falsely settling the withdrawal.
#[test]
fn a_failed_rule_teardown_does_not_publish_or_settle_the_withdrawal() {
    let (steering, agent) = acknowledged_steering(true);
    let destinations = [destination("10.96.0.10", 5300)];
    assert_eq!(
        steering.reconcile_with(&ifaces(), &destinations, true),
        SteerReconcileOutcome::Applied
    );
    agent.take_entries();

    agent
        .fail_teardown
        .store(true, std::sync::atomic::Ordering::SeqCst);
    for _ in 0..2 {
        assert_eq!(
            steering.reconcile_with(&ifaces(), &[], false),
            SteerReconcileOutcome::Failed
        );
        assert_eq!(
            agent.take_entries(),
            vec!["script:teardown".to_string()],
            "an unproven rule removal must retry without publishing the empty generation"
        );
    }

    agent
        .fail_teardown
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        steering.reconcile_with(&ifaces(), &[], false),
        SteerReconcileOutcome::Removed
    );
    assert_eq!(
        agent.entries(),
        vec![
            "script:teardown".to_string(),
            "publish:withdraw".to_string()
        ]
    );
    forget(steering);
}

/// A failed outgoing-generation teardown also fences an update: the replacement
/// desired generation is not published and setup cannot run until the stale
/// rules are proven gone.
#[test]
fn a_failed_rule_teardown_fences_replacement_publication_and_setup() {
    let (steering, agent) = acknowledged_steering(true);
    let first = [destination("10.96.0.10", 5300)];
    let second = [destination("10.96.0.11", 5301)];
    assert_eq!(
        steering.reconcile_with(&ifaces(), &first, true),
        SteerReconcileOutcome::Applied
    );
    agent.take_entries();

    agent
        .fail_teardown
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        steering.reconcile_with(&ifaces(), &second, true),
        SteerReconcileOutcome::Failed
    );
    assert_eq!(agent.take_entries(), vec!["script:teardown".to_string()]);

    agent
        .fail_teardown
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        steering.reconcile_with(&ifaces(), &second, true),
        SteerReconcileOutcome::Applied
    );
    assert_eq!(
        agent.entries(),
        vec![
            "script:teardown".to_string(),
            "publish:1".to_string(),
            "script:setup".to_string()
        ]
    );
    forget(steering);
}

/// A withdrawal is not DONE when it is requested — it is done when the
/// node-agent has proven the empty generation live. Reporting it settled early
/// would leave a revoked ClusterIP admissible to enrolled pods with no serving
/// socket for the life of the process, because the quiet-poll short-circuit
/// would then report `Unchanged` forever.
#[test]
fn a_withdrawal_is_not_proven_until_the_empty_generation_is_acknowledged() {
    let (steering, agent) = acknowledged_steering(false);
    let destinations = [destination("10.96.0.10", 5300)];

    steering.reconcile_with(&ifaces(), &destinations, true);
    agent.acknowledge_latest();
    assert_eq!(
        steering.reconcile_with(&ifaces(), &destinations, true),
        SteerReconcileOutcome::Applied
    );
    agent.take_entries();

    // The listener stops. The rules go immediately; the proof does not.
    assert_eq!(
        steering.reconcile_with(&ifaces(), &[], false),
        SteerReconcileOutcome::PendingAck,
        "an unacknowledged withdrawal must not be reported as removed"
    );
    assert_eq!(
        agent.take_entries(),
        vec![
            "script:teardown".to_string(),
            "publish:withdraw".to_string()
        ]
    );

    // Still unproven: the next quiet poll must RE-attempt rather than settle.
    assert_eq!(
        steering.reconcile_with(&ifaces(), &[], false),
        SteerReconcileOutcome::PendingAck
    );
    let retried = agent.take_entries();
    assert!(
        retried.contains(&"publish:withdraw".to_string()),
        "an unproven withdrawal must be retried on the next reconcile: {retried:?}"
    );
    assert!(
        !retried.contains(&"script:teardown".to_string()),
        "the rules are already proven gone; only the proof is missing: {retried:?}"
    );

    // The node-agent proves the empty generation live. The withdrawal is now
    // settled, so the loop stops issuing commands entirely.
    agent.acknowledge_latest();
    assert_eq!(
        steering.reconcile_with(&ifaces(), &[], false),
        SteerReconcileOutcome::Unchanged
    );
    assert!(
        agent.entries().is_empty(),
        "a proven withdrawal must run no command at all"
    );
    forget(steering);
}

/// A withdrawal whose PUBLICATION fails is a hard failure, distinct from one
/// merely waiting for the node-agent — and it is never recorded as done.
/// Without this, one transient I/O error would leave a revoked ClusterIP
/// authorized for the life of the process, because the quiet-poll short-circuit
/// would report `Unchanged` forever.
#[test]
fn a_failed_withdrawal_is_retried_rather_than_settled() {
    let (steering, agent) = acknowledged_steering(true);
    let destinations = [destination("10.96.0.10", 5300)];

    assert_eq!(
        steering.reconcile_with(&ifaces(), &destinations, true),
        SteerReconcileOutcome::Applied
    );

    // The listener stops while the channel is unwritable.
    agent
        .fail_publish
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        steering.reconcile_with(&ifaces(), &[], false),
        SteerReconcileOutcome::Failed
    );
    agent.take_entries();

    // Still failing: the next quiet poll must RE-attempt the withdrawal instead
    // of settling.
    assert_eq!(
        steering.reconcile_with(&ifaces(), &[], false),
        SteerReconcileOutcome::Failed
    );
    let retried = agent.take_entries();
    assert!(
        retried
            .iter()
            .any(|entry| entry.starts_with("publish:withdraw")),
        "an unproven withdrawal must be retried on the next reconcile: {retried:?}"
    );

    // Once it succeeds and is acknowledged, the loop settles.
    agent
        .fail_publish
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        steering.reconcile_with(&ifaces(), &[], false),
        SteerReconcileOutcome::Removed
    );
    agent.take_entries();
    assert_eq!(
        steering.reconcile_with(&ifaces(), &[], false),
        SteerReconcileOutcome::Unchanged
    );
    assert!(agent.entries().is_empty());
    forget(steering);
}

/// A publication that cannot be written fails the WHOLE generation closed: no
/// steering rules are installed, so the Service path stays on its pre-existing
/// fail-closed posture (dropped at the pod-veth guard) rather than becoming a
/// steered black hole.
#[test]
fn a_failed_publication_refuses_the_generation_and_steers_nothing() {
    let (steering, agent) = acknowledged_steering(true);
    agent
        .fail_publish
        .store(true, std::sync::atomic::Ordering::SeqCst);

    assert_eq!(
        steering.reconcile_with(&ifaces(), &[destination("10.96.0.10", 5300)], true),
        SteerReconcileOutcome::Failed
    );
    let recorded = agent.entries();
    assert!(
        !recorded.contains(&"script:setup".to_string()),
        "no steering rule may be installed for a generation whose reply sources \
         could not be published: {recorded:?}"
    );
    assert!(
        recorded.iter().any(|entry| entry.ends_with(":failed")),
        "the failure must be observed: {recorded:?}"
    );
    forget(steering);
}

/// A hard publication failure is DISTINCT from a pending acknowledgement, and
/// so is an unreadable acknowledgement: neither may be mistaken for the settled
/// applied generation, and both keep the datapath torn down.
#[test]
fn an_unreadable_acknowledgement_fails_the_generation_closed() {
    let (steering, agent) = acknowledged_steering(true);
    agent
        .fail_read_ack
        .store(true, std::sync::atomic::Ordering::SeqCst);

    assert_eq!(
        steering.reconcile_with(&ifaces(), &[destination("10.96.0.10", 5300)], true),
        SteerReconcileOutcome::Failed,
        "an acknowledgement that cannot be read proves nothing"
    );
    let recorded = agent.entries();
    assert!(
        !recorded.contains(&"script:setup".to_string()),
        "an unprovable generation must steer nothing: {recorded:?}"
    );

    agent
        .fail_read_ack
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        steering.reconcile_with(&ifaces(), &[destination("10.96.0.10", 5300)], true),
        SteerReconcileOutcome::Applied,
        "and the recovery is the ordinary next reconcile"
    );
    forget(steering);
}

/// A restart republishes from sequence 1 under a NEW owner. The predecessor's
/// acknowledgement is still on disk naming ITS owner, so it must not satisfy
/// the successor's first generation — otherwise a fresh process would steer
/// immediately on a proof about a set the node may no longer hold.
#[test]
fn a_predecessor_acknowledgement_does_not_let_a_successor_steer() {
    let registry = tempfile::tempdir().expect("registry dir");
    let destinations = [destination("10.96.0.10", 5300)];

    // The predecessor publishes and is acknowledged, then the process dies.
    let predecessor = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let old = predecessor
        .publish(&destinations, true)
        .expect("predecessor");
    write_acknowledgement(registry.path(), &old).expect("predecessor acknowledgement");

    let log = Arc::new(Mutex::new(Vec::new()));
    let auto = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let publisher = RecordingPublisher {
        inner: RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID)),
        registry: registry.path().to_path_buf(),
        log: log.clone(),
        fail_publish: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        fail_read_ack: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        auto_acknowledge: auto,
    };
    let steering = NodeWaypointUdpSteering::new(Arc::new(SharedLogBackend {
        log: log.clone(),
        fail_teardown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    }))
    .with_reply_source_publisher(Arc::new(publisher));

    assert_eq!(
        steering.reconcile_with(&ifaces(), &destinations, true),
        SteerReconcileOutcome::PendingAck,
        "a predecessor's acknowledgement must not prove the successor's generation"
    );
    let recorded = log.lock().expect("shared log").clone();
    assert!(
        !recorded.contains(&"script:setup".to_string()),
        "the successor must wait for its OWN acknowledgement: {recorded:?}"
    );

    // The live node-agent acknowledges the successor's generation.
    let desired = read_desired_generation(registry.path())
        .expect("read desired generation")
        .expect("a generation is published");
    write_acknowledgement(registry.path(), &desired.generation).expect("acknowledgement");
    assert_eq!(
        steering.reconcile_with(&ifaces(), &destinations, true),
        SteerReconcileOutcome::Applied
    );
    forget(steering);
}

/// A quiet poll on an UNCHANGED, ACKNOWLEDGED serving generation must not
/// re-publish either — the reply-source set is part of the applied generation,
/// not a per-poll write.
#[test]
fn an_unchanged_generation_republishes_nothing() {
    let (steering, agent) = acknowledged_steering(true);
    let destinations = [destination("10.96.0.10", 5300)];

    assert_eq!(
        steering.reconcile_with(&ifaces(), &destinations, true),
        SteerReconcileOutcome::Applied
    );
    agent.take_entries();
    assert_eq!(
        steering.reconcile_with(&ifaces(), &destinations, true),
        SteerReconcileOutcome::Unchanged
    );
    assert!(agent.entries().is_empty());
    forget(steering);
}

/// A bound listener with no ClusterIP destinations still publishes ACTIVE so
/// the relay-cgroup sender proof stays live. Steering rules stay absent.
#[test]
fn a_serving_headless_listener_keeps_the_sender_proof_without_steering() {
    let (steering, agent) = acknowledged_steering(true);

    assert_eq!(
        steering.reconcile_with(&ifaces(), &[], true),
        SteerReconcileOutcome::Applied,
        "a bound headless listener is serving, not withdrawn"
    );
    assert_eq!(
        agent.entries(),
        vec![
            "script:teardown".to_string(),
            "publish:active:0".to_string(),
        ],
        "rules stay absent; the active-empty generation is published so the sender proof can settle"
    );
    assert!(steering.serving());
    assert!(steering.bound_destinations().is_empty());

    agent.take_entries();

    assert_eq!(
        steering.reconcile_with(&ifaces(), &[], true),
        SteerReconcileOutcome::Unchanged
    );
    assert!(
        agent.take_entries().is_empty(),
        "a quiet poll of a proven active-empty generation must run no command"
    );
    forget(steering);
}

/// Adding and removing ClusterIP destinations while the listener stays bound
/// must not withdraw the sender proof. Only losing the last serving listener
/// (or shutdown) is a true withdrawal.
#[test]
fn clusterip_churn_while_serving_does_not_withdraw_the_sender_proof() {
    let (steering, agent) = acknowledged_steering(true);
    let dest = [
        destination("10.96.0.10", 5300),
        destination("fd00::a", 5300),
    ];

    assert_eq!(
        steering.reconcile_with(&ifaces(), &dest, true),
        SteerReconcileOutcome::Applied
    );
    agent.take_entries();

    assert_eq!(
        steering.reconcile_with(&ifaces(), &[], true),
        SteerReconcileOutcome::Applied,
        "dropping every ClusterIP while the listener stays bound is still ACTIVE"
    );
    let emptied = agent.take_entries();
    assert!(
        emptied.contains(&"script:teardown".to_string())
            && emptied.contains(&"publish:active:0".to_string())
            && !emptied.contains(&"publish:withdraw".to_string()),
        "ClusterIP removal must not publish a withdrawal: {emptied:?}"
    );

    assert_eq!(
        steering.reconcile_with(&ifaces(), &dest, true),
        SteerReconcileOutcome::Applied
    );
    let restored = agent.take_entries();
    assert!(
        restored.contains(&"publish:2".to_string())
            && restored.contains(&"script:setup".to_string()),
        "restoring ClusterIPs while still serving must re-authorize then steer: {restored:?}"
    );

    assert_eq!(
        steering.reconcile_with(&ifaces(), &[], false),
        SteerReconcileOutcome::Removed
    );
    assert_eq!(
        agent.entries(),
        vec![
            "script:teardown".to_string(),
            "publish:withdraw".to_string()
        ],
        "losing the last serving listener is the only true withdrawal"
    );
    forget(steering);
}

/// Empty attribution interfaces leave steering rules absent, but a bound
/// listener still publishes ACTIVE (with its ClusterIP tuples, if any) so the
/// direct-node sender proof stays live.
#[test]
fn serving_without_attribution_interfaces_keeps_the_sender_proof() {
    let (steering, agent) = acknowledged_steering(true);
    let dest = [destination("10.96.0.10", 5300)];

    assert_eq!(
        steering.reconcile_with(&[], &dest, true),
        SteerReconcileOutcome::Applied
    );
    let entries = agent.entries();
    assert!(
        entries.contains(&"script:teardown".to_string())
            && entries.contains(&"publish:1".to_string())
            && !entries.contains(&"script:setup".to_string())
            && !entries.contains(&"publish:withdraw".to_string()),
        "no interfaces means no steering rules, but the sender proof stays live: {entries:?}"
    );
    forget(steering);
}

/// Shutdown must withdraw the authorization, not just the rules: a proxy that
/// exits leaving a ClusterIP admissible has left the guard permanently weaker
/// than it found it.
#[test]
fn shutdown_withdraws_every_authorized_reply_source() {
    let (steering, agent) = acknowledged_steering(true);

    assert_eq!(
        steering.reconcile_with(&ifaces(), &[destination("10.96.0.10", 5300)], true),
        SteerReconcileOutcome::Applied
    );
    agent.take_entries();

    steering.shutdown();
    assert_eq!(
        agent.entries(),
        vec![
            "script:teardown".to_string(),
            "publish:withdraw".to_string()
        ],
        "shutdown must un-steer and then withdraw every authorization"
    );
    forget(steering);
}

// ── Service-path tools image (hosted live gate, issue #3286) ───────────────
//
// Direct NodeWaypoint listener probes bind a host UDP socket and do not need
// iptables. The Service/ClusterIP path does: HostNamespaceSteerBackend runs
// `sh -c` scripts. The distroless `-ebpf` image has neither `sh` nor iptables,
// so a NodeWaypoint that enables UDP listeners on that image materializes the
// listener (direct probes pass) and then never steers ClusterIP traffic
// (backend_hits=0). These tests pin the chart/workflow contract that would
// have caught that hosted failure without executing cargo or the live fixture.

fn repo_file(rel: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", path.display());
    })
}

/// The production backend is a `sh -c` of generated iptables/ip scripts. An
/// image without `/bin/sh` fails every teardown with ENOENT and never installs
/// steering — the exact hosted Service-path failure.
#[test]
fn production_steer_backend_executes_generated_scripts_through_sh() {
    let source = repo_file("src/proxy/node_waypoint_udp_steering.rs");
    assert!(
        source.contains("Command::new(\"sh\")"),
        "HostNamespaceSteerBackend must exec the generated script through sh"
    );
    assert!(
        source.contains(".arg(\"-c\")"),
        "HostNamespaceSteerBackend must pass the generated script as sh -c"
    );
}

/// Helm must promote the ambient proxy to `-ebpf-tools` when NodeWaypoint UDP
/// listeners are enabled, and must leave TCP-only NodeWaypoint plus the
/// node-agent on distroless `-ebpf`.
#[test]
fn node_waypoint_udp_listeners_select_the_tools_capable_runtime() {
    let chart = repo_file("charts/ferrum-mesh/templates/ambient-daemonset.yaml");
    assert!(
        chart.contains("$nodeWaypointUdpListeners"),
        "the chart must parse FERRUM_MESH_NODE_WAYPOINT_UDP_LISTENERS_ENABLED"
    );
    assert!(
        chart.contains("FERRUM_MESH_NODE_WAYPOINT_UDP_LISTENERS_ENABLED"),
        "the chart must read the UDP listener enablement env from ambient.env"
    );
    assert!(
        chart.contains("{{- if or $ambientUdpLifecycle $nodeWaypointUdpListeners -}}"),
        "enabling NodeWaypoint UDP listeners must select the tools-capable image"
    );
    assert!(
        chart.contains("include \"ferrum-mesh.toolsImageTag\" $ambientImageTag"),
        "Ambient and injector shell consumers must share tools-tag promotion"
    );
    let helpers = repo_file("charts/ferrum-mesh/templates/_helpers.tpl");
    assert!(helpers.contains("trimSuffix \"-ebpf\" ."));
    assert!(helpers.contains("hasSuffix \"-ebpf-tools\" ."));

    let node_agent = repo_file("charts/ferrum-mesh/templates/node-agent-daemonset.yaml");
    assert!(
        !node_agent.contains("-ebpf-tools"),
        "the node-agent must not adopt the tools-capable image; only the pod \
         that shells out receives that attack surface"
    );
}

/// The hosted live job must package and load the tools image the chart names
/// when UDP listeners are enabled. Packaging only `-ebpf` leaves kind with
/// ImagePullBackOff (or, before helm selected tools, ENOENT on `sh`).
#[test]
fn node_waypoint_ebpf_live_job_packages_and_loads_the_tools_image() {
    let workflow = repo_file(".github/workflows/node-waypoint-ebpf-live.yml");
    assert!(
        workflow.contains("Dockerfile.ebpf-tools-layer"),
        "the live job must build the tools-capable image the chart selects"
    );
    assert!(
        workflow.contains("${{ env.FERRUM_IMAGE_TAG }}-ebpf-tools"),
        "the live job must tag the tools image with the chart's -ebpf-tools suffix"
    );
    assert!(
        workflow.contains(
            "kind load docker-image \"${FERRUM_IMAGE_REPOSITORY}:${FERRUM_IMAGE_TAG}-ebpf-tools\""
        ),
        "kind must receive the tools image before helm install"
    );
    assert!(
        workflow.contains("for tool in ip iptables ip6tables iptables-save ip6tables-save; do"),
        "the live job must prove the packaged tools image can execute steering tools"
    );

    let layer = repo_file("Dockerfile.ebpf-tools-layer");
    assert!(
        layer.contains("ca-certificates"),
        "the tools layer must install the Debian platform CA bundle for plugin \
         reqwest TLS verification"
    );
    assert!(
        layer.contains("test -x /bin/sh"),
        "the tools layer must fail the build if /bin/sh is missing"
    );
    assert!(
        layer.contains("test -s /etc/ssl/certs/ca-certificates.crt"),
        "the tools layer must fail the build if the Debian platform CA bundle is missing"
    );
    assert!(
        layer.contains("iptables"),
        "the tools layer must install iptables for Service-path steering"
    );
    assert!(
        layer.contains("FROM ${TOOLS_BASE}"),
        "the tools layer is a separate Debian image, not a weakening of distroless -ebpf"
    );

    let harness = repo_file("tests/k8s/node_waypoint_ebpf_live/run.sh");
    assert!(
        harness.contains("FERRUM_MESH_NODE_WAYPOINT_UDP_LISTENERS_ENABLED=true"),
        "the live harness must enable UDP listeners so the chart selects -ebpf-tools"
    );
    assert!(
        harness.contains("IMAGE_TAG-ebpf-tools"),
        "the live harness must assert the UDP-listeners render selects -ebpf-tools"
    );
    assert!(
        harness.contains("TCP-only NodeWaypoint unexpectedly selected the tools-capable"),
        "the live harness must keep TCP-only NodeWaypoint on distroless -ebpf"
    );
}
