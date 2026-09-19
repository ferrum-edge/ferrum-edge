//! Mesh traffic-capture planning (Layer 7).
//!
//! The proxy hot path never shells out to iptables or eBPF. This module builds
//! declarative plans that init containers / node agents can apply outside the
//! request path.

use std::net::IpAddr;

use tracing::warn;

use crate::config::conf_file::resolve_ferrum_var;
use crate::startup::quoted_config_value;

pub const DEFAULT_PROXY_UID: u32 = 1337;
pub(crate) const XTABLES_LOCK_WAIT_SECONDS: u8 = 5;

/// Default UDP TPROXY listener port (Stage 3 consumer). Distinct from the TCP
/// outbound REDIRECT port (15001) because UDP and TCP cannot share one listener
/// socket — a UDP datagram delivered transparently by TPROXY has to land on a
/// `SO_REUSEADDR`/`IP_TRANSPARENT` UDP socket, not the TCP outbound listener.
pub const DEFAULT_UDP_OUTBOUND_PORT: u16 = 15011;

/// Default firewall mark (a.k.a. `fwmark`) stamped on TPROXY'd UDP datagrams so
/// the policy routing rule (`ip rule add fwmark <mark> lookup <table>`) steers
/// them to the local-delivery table. `0x733` == 1843 decimal.
///
/// **Ferrum-owned, deliberately NOT Istio's `0x539` (codex r3).** The default
/// must NOT collide with a co-resident Istio install's marks. Ferrum's higher-
/// priority fwmark `ip rule` (priority [`TPROXY_ROUTE_RULE_PRIORITY`] == 100,
/// below `main`) matches this mark and steers it to the Ferrum-owned table
/// [`TPROXY_ROUTE_TABLE`]; if the default were Istio's conventional TPROXY mark
/// `0x539`, Istio's own marked packets would be hijacked into Ferrum's table and
/// Istio traffic would break. `0x733` sits outside Istio
/// (`0x539`/`0x53a`/`0x111`/`0x222`), Cilium masked mark classes
/// (`0x200`/`0xA00`/`0xF00`/`0x800`), and Calico (`0x10000`+) marks.
///
/// Collision analysis (within Ferrum): Ferrum uses NO other packet marks
/// anywhere (verified: the only `1337` is the proxy `--uid-owner` UID, a *socket
/// owner* match in a disjoint namespace from `skb->mark`, and
/// `node_agent_hbone_redirect_port` `16008` is a port, not a mark). Operators
/// can override via `FERRUM_MESH_TPROXY_MARK`.
pub const DEFAULT_TPROXY_MARK: u32 = 0x733;

// Compile-time guards on the default mark, at MODULE level (NOT `cfg(test)`) so a
// regression fails ANY build — `cargo build`/release — not only `cargo test`:
//  - codex r3: the default must be Ferrum-owned and NOT Istio's conventional
//    TPROXY mark `0x539`. With Ferrum's higher-priority fwmark rule (priority
//    100) matching the mark, defaulting to `0x539` would hijack a co-resident
//    Istio's marked packets into Ferrum's table and break Istio traffic.
//  - the default must not ALIAS a co-resident CNI's masked magic-mark class:
//    Cilium matches `skb->mark & 0xF00`, so the prior `0xFE3` aliased the `0xF00`
//    class (`0xFE3 & 0xF00 == 0xF00`); `0x733 & 0xF00 == 0x700` does not.
const _: () = assert!(
    DEFAULT_TPROXY_MARK != 0x539,
    "default TPROXY mark must not collide with Istio's conventional `0x539`"
);
const _: () = assert!(
    DEFAULT_TPROXY_MARK == 0x733,
    "default TPROXY mark is the Ferrum-owned `0x733` (1843)"
);
const _: () = assert!(
    (DEFAULT_TPROXY_MARK & 0xF00) != 0xF00,
    "default TPROXY mark must not alias CNI 0xF00/0xF00 masked mark class"
);
const _: () = assert!(
    (DEFAULT_TPROXY_MARK & 0xF00) != 0xA00,
    "default TPROXY mark must not alias CNI 0xA00/0xF00 masked mark class"
);
const _: () = assert!(
    (DEFAULT_TPROXY_MARK & 0xF00) != 0x800,
    "default TPROXY mark must not alias CNI 0x800/0xF00 masked mark class"
);
const _: () = assert!(
    (DEFAULT_TPROXY_MARK & 0xF00) != 0x200,
    "default TPROXY mark must not alias CNI 0x200/0xF00 masked mark class"
);

/// `skb->mark` mask matched alongside [`DEFAULT_TPROXY_MARK`]. A full-width mask
/// keeps the TPROXY mark from aliasing onto other mark bits a co-resident CNI
/// might use; rendered as `<mark>/<mask>` in the `--tproxy-mark` argument and as
/// the `ip rule` `fwmark <mark>/<mask>` selector.
pub(crate) const TPROXY_MARK_MASK: u32 = 0xffff_ffff;

/// Dedicated **Ferrum-owned** policy routing table for transparent UDP local
/// delivery. Deliberately NOT Istio's inbound-TPROXY table `133`: a co-resident
/// Istio install owns `133`, so cleanup must never flush it. This high constant
/// is unlikely to collide with another component's table; combined with
/// exact-rule/exact-route teardown (never `ip route flush table`), Ferrum only
/// ever removes routing state it created. Inert until the Stage 3 UDP listener
/// binds.
pub(crate) const TPROXY_ROUTE_TABLE: u16 = 33133;

/// Explicit `ip rule` priority for the Ferrum UDP TPROXY fwmark selector.
///
/// Two things this controls, kept deliberately SEPARATE from the routing TABLE
/// number ([`TPROXY_ROUTE_TABLE`]):
/// 1. **Idempotency / exact teardown.** An explicit priority makes setup
///    delete-by-priority before add (so a node-agent fallback crash/retry never
///    appends a duplicate rule) and lets cleanup delete the EXACT Ferrum-owned
///    rule (`ip rule del priority <P>`) instead of `ip rule del lookup <table>`
///    (which would also drop an unrelated rule pointing at the same table).
/// 2. **RPDB ordering — MUST sit BELOW the kernel's built-in `main` table rule.**
///    The routing policy database is priority-ordered (lowest number wins) and
///    the kernel installs `main` at priority **32766**. If Ferrum's fwmark rule
///    sat ABOVE 32766, `main` would resolve a marked datagram to its normal
///    (forwarding/remote) route BEFORE the fwmark rule ever steered it to the
///    local-delivery table — transparent local delivery would never engage and
///    captured UDP would silently black-hole. A low constant (`100`) keeps the
///    fwmark lookup ahead of `main` (and of `local` at 0, which only matches
///    genuinely-local destinations and never the marked egress). The TABLE
///    number stays the high Ferrum-owned `33133`; only this RULE priority is low.
pub(crate) const TPROXY_ROUTE_RULE_PRIORITY: u32 = 100;

/// Two alternating fail-closed chains used by the Ambient per-pod UDP
/// producer. A replacement chain is fully populated and jumped from OUTPUT
/// before the previous chain is removed, so guarded retries never create a
/// fail-open gap by flushing the currently active guard.
const UDP_FAIL_CLOSED_CHAIN_A: &str = "FERRUM_UDP_FAIL_CLOSED_A";
const UDP_FAIL_CLOSED_CHAIN_B: &str = "FERRUM_UDP_FAIL_CLOSED_B";

/// The single `mangle PREROUTING` chain holding the HOST-network UDP capture
/// rules (issue #3288). Deliberately distinct from the pod-netns chain names
/// (`FERRUM_MESH_UDP_OUTBOUND` / `_INBOUND` / `_OUTPUT_MARK` / `_REINJECT`) so
/// host-netns and pod-netns state can never be confused by a teardown: each
/// path only ever removes objects it owns by exact name.
pub(crate) const UDP_HOST_CAPTURE_CHAIN: &str = "FERRUM_MESH_UDP_HOST";

/// Alternating fail-closed DROP guards for the host-netns UDP capture path.
/// Same A/B replacement discipline as the pod-netns guards, but jumped from
/// `mangle PREROUTING` (host-netns pod egress is FORWARDED, so it never
/// traverses `OUTPUT`) and scoped to the enrolled pods' host-side interfaces.
pub(crate) const UDP_HOST_GUARD_CHAIN_A: &str = "FERRUM_MESH_UDP_HOST_GUARD_A";
pub(crate) const UDP_HOST_GUARD_CHAIN_B: &str = "FERRUM_MESH_UDP_HOST_GUARD_B";

/// Dedicated **Ferrum-owned** policy routing table for HOST-netns transparent
/// UDP local delivery, deliberately DIFFERENT from the pod-netns
/// [`TPROXY_ROUTE_TABLE`] (`33133`) and from the node-agent's tc ingress-redirect
/// table (`33134`).
///
/// The pod-netns and host-netns paths normally live in different network
/// namespaces, but a misconfigured registry entry, a `hostNetwork` workload, or
/// a future co-resident deployment could put both in the SAME namespace. Giving
/// the host path its own table + rule priority means neither path's teardown can
/// ever remove the other's routing state — ownership stays exact.
pub(crate) const TPROXY_HOST_ROUTE_TABLE: u16 = 33135;

/// `ip rule` priority for the host-netns UDP fwmark selector. Like
/// [`TPROXY_ROUTE_RULE_PRIORITY`] it MUST sit below the kernel's `main` rule
/// (32766) or transparent local delivery never engages; it is one above the
/// pod-netns priority so the two rules are individually addressable for exact
/// delete-by-priority teardown.
pub(crate) const TPROXY_HOST_ROUTE_RULE_PRIORITY: u32 = 101;

const _: () = assert!(
    TPROXY_HOST_ROUTE_TABLE != TPROXY_ROUTE_TABLE,
    "host-netns UDP routing table must be distinct from the pod-netns table"
);
const _: () = assert!(
    TPROXY_HOST_ROUTE_RULE_PRIORITY != TPROXY_ROUTE_RULE_PRIORITY,
    "host-netns UDP rule priority must be distinct from the pod-netns priority"
);
const _: () = assert!(
    TPROXY_HOST_ROUTE_RULE_PRIORITY < 32766,
    "host-netns UDP fwmark rule must sort below the kernel `main` table rule"
);

/// Linux `IFNAMSIZ` is 16 bytes including the NUL terminator, so an interface
/// name is at most 15 characters.
const MAX_INTERFACE_NAME_LEN: usize = 15;

/// Upper bound on host capture interfaces folded into one plan. Each interface
/// multiplies the emitted rule count by the number of capture selectors, and the
/// plan is rebuilt on every enrolled-pod change, so an unbounded set would turn
/// pod churn into an unbounded `iptables` workload. Nodes do not run anywhere
/// near this many mesh-enrolled pods; exceeding it is a configuration error and
/// fails closed rather than installing a partial ruleset.
pub const MAX_HOST_UDP_CAPTURE_INTERFACES: usize = 512;

// ── NodeWaypoint UDP/DTLS Service steering (issue #3286) ────────────────────
//
// A NodeWaypoint materializes one host-netns wildcard UDP/DTLS listener per
// in-mesh Service port. Nothing steers ordinary Service traffic there: an
// enrolled workload sends to `<ClusterIP>:<port>`, kube-proxy's `nat
// PREROUTING` DNATs that to a backing pod, and the datagram is forwarded to the
// pod — where the pod-veth `ferrum_tc_inbound` guard drops it because it does
// not carry the relay's auth mark. So the Service path is not merely a bypass,
// it is a black hole, and only a direct dial to a NODE address reaches the
// listener at all.
//
// These rules close that gap without rewriting a single packet field:
//
//   raw    PREROUTING -i <pod veth> -p udp -d <ClusterIP> --dport <port>
//              -j CT --notrack
//   mangle PREROUTING -i <pod veth> -p udp -d <ClusterIP> --dport <port>
//              -j MARK --set-xmark <mark>/<mask>
//   ip rule add priority <prio> fwmark <mark>/<mask> lookup <table>
//   ip route add local <default> dev lo table <table>
//
// * `--notrack` runs in `raw` (priority -300), BEFORE conntrack (-200), so the
//   `nat` table is never consulted for these flows and kube-proxy cannot DNAT
//   them out from under the waypoint. It also makes the steering independent of
//   which endpoint kube-proxy would have chosen: the waypoint does its own
//   authorized endpoint selection.
// * `MARK` + the `local` route make the datagram LOCALLY DELIVERED while its IP
//   header still carries the ClusterIP. The listener's wildcard socket receives
//   it by the ordinary UDP lookup, and `IP_PKTINFO`/`IPV6_PKTINFO` reports the
//   original destination (`fib_compute_spec_dst` returns `iph->daddr` for an
//   `RTCF_LOCAL` route) together with the pod's ingress interface — the exact
//   evidence NodeWaypoint source attribution already consumes. Replies are
//   sourced back from the ClusterIP through the listener's transparent socket.
// * `-i <pod veth>` is the direction discriminator, identical to the Ambient
//   host capture path: only a pod's own egress enters the host namespace on
//   that pod's interface. Node-local traffic is locally generated and traverses
//   `OUTPUT`, which is deliberately never hooked, so the waypoint's own relay
//   dials and replies can never be re-steered into itself.
// * `-d <ClusterIP> --dport <port>` is the service identity. Port-only scoping
//   would capture a workload's traffic to an unrelated off-cluster host that
//   happens to use the same port number and relay it to a mesh service's
//   endpoints, so the destination address is always part of the match.

/// `raw`-table chain holding the NodeWaypoint Service-steering conntrack
/// exemptions.
pub(crate) const NODE_WAYPOINT_UDP_STEER_NOTRACK_CHAIN: &str = "FERRUM_NW_UDP_NOTRACK";

/// `mangle`-table chain holding the NodeWaypoint Service-steering marks.
pub(crate) const NODE_WAYPOINT_UDP_STEER_CHAIN: &str = "FERRUM_NW_UDP_STEER";

/// Firewall mark stamped on a steered datagram. Ferrum-owned and distinct from
/// every other mark this datapath uses, because each selects a different
/// routing outcome and an alias would cross them.
pub const NODE_WAYPOINT_UDP_STEER_MARK: u32 = 0x736;

/// Full-width mask, matching the UDP TPROXY convention, so the steering mark
/// cannot alias onto a co-resident CNI's mark bits.
pub(crate) const NODE_WAYPOINT_UDP_STEER_MARK_MASK: u32 = 0xffff_ffff;

/// Ferrum-owned routing table for steered local delivery. Distinct from the
/// pod-netns TPROXY table (`33133`), the tc ingress-redirect table (`33134`),
/// and the host UDP capture table (`33135`), so tearing one down can never reap
/// another.
pub(crate) const NODE_WAYPOINT_UDP_STEER_TABLE: u16 = 33136;

/// RPDB priority for the steering fwmark rule. Must sort BELOW the kernel
/// `main` rule at 32766 (lower number = evaluated first) or the marked datagram
/// resolves as forwardable and is never delivered locally.
pub(crate) const NODE_WAYPOINT_UDP_STEER_RULE_PRIORITY: u32 = 102;

const _: () = assert!(
    NODE_WAYPOINT_UDP_STEER_MARK != DEFAULT_TPROXY_MARK,
    "the NodeWaypoint UDP steering mark must not alias the UDP TPROXY mark"
);
const _: () = assert!(
    NODE_WAYPOINT_UDP_STEER_MARK != 0x734 && NODE_WAYPOINT_UDP_STEER_MARK != 0x735,
    "the NodeWaypoint UDP steering mark must not alias the relay auth mark (0x734) or the tc \
     ingress-redirect mark (0x735); a steered datagram would then be routed as a relayed one"
);
const _: () = assert!(
    NODE_WAYPOINT_UDP_STEER_RULE_PRIORITY < 32766,
    "the NodeWaypoint UDP steering fwmark rule must sort below the kernel `main` table rule"
);
const _: () = assert!(
    NODE_WAYPOINT_UDP_STEER_TABLE != TPROXY_ROUTE_TABLE
        && NODE_WAYPOINT_UDP_STEER_TABLE != TPROXY_HOST_ROUTE_TABLE,
    "the NodeWaypoint UDP steering table must be distinct from every other Ferrum-owned table"
);

/// Upper bound on steered `(ClusterIP, port)` destinations in one plan. Each
/// destination is multiplied by the enrolled-interface count in BOTH emitted
/// chains, so an unbounded set would turn a large slice into an unbounded
/// `iptables` workload on every reconcile. Exceeding it fails the plan closed
/// rather than installing a partial (and therefore silently service-losing)
/// ruleset.
pub const MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS: usize = 128;

/// One steered Service destination: the address a workload actually addresses
/// and the port the materialized listener serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeWaypointUdpSteerDestination {
    pub ip: std::net::IpAddr,
    pub port: u16,
}

impl NodeWaypointUdpSteerDestination {
    /// Render the `-d <ip>/<prefix> --dport <port>` match. The address is
    /// re-rendered from the parsed `IpAddr`, never from operator text, so
    /// nothing that reaches the `sh -c` script can carry shell metacharacters.
    fn selector(&self) -> String {
        let prefix = if self.ip.is_ipv4() { 32 } else { 128 };
        format!("-p udp -d {}/{} --dport {}", self.ip, prefix, self.port)
    }
}

/// Per-family NodeWaypoint UDP steering commands.
///
/// Ordering is load-bearing and fail-closed, and the FIRST step is the one that
/// makes a generation change safe:
///
/// 1. **Create-and-empty the `mangle` mark chain before anything else.** From
///    this instant nothing is marked at all, so no datagram can be steered under
///    a destination generation whose `--notrack` and local-delivery
///    prerequisites have not been installed yet. This opens a brief window where
///    the Service path is unsteered — which is exactly the pre-existing
///    fail-closed posture (the pod-veth guard drops the datagram) — and closes
///    the window where a previous generation's mark survived while its `raw`
///    exemption had already been flushed. In that window `nat PREROUTING` would
///    have DNAT-ed the flow to a backing pod and the still-live mark would then
///    have delivered THAT rewritten datagram locally: cross-generation,
///    wrong-destination admission. A short outage is acceptable; that is not.
/// 2. `ip rule` / `ip route local` next. Marking without local delivery is a
///    black hole, so the routing exists before anything can be marked.
/// 3. The `raw` `--notrack` chain, its rules, and its `PREROUTING` jump, so no
///    steered flow can be conntracked (and therefore DNAT-ed).
/// 4. The `mangle` rules and the mangle `PREROUTING` jump LAST — the moment
///    steering becomes observable again, and by then every prerequisite for
///    exactly these destinations is already installed.
///
/// Both chains are flushed and repopulated behind a STABLE `PREROUTING` jump,
/// so a reconcile changes chain CONTENTS only and a crash mid-reconcile can
/// leave at worst a subset of the intended rules behind an empty-or-partial
/// chain, never an orphaned jump and never a mark without its prerequisites.
fn node_waypoint_udp_steer_commands_for_family(
    binary: &str,
    ipv6: bool,
    ifaces: &[String],
    destinations: &[NodeWaypointUdpSteerDestination],
) -> Vec<String> {
    let family_destinations: Vec<&NodeWaypointUdpSteerDestination> = destinations
        .iter()
        .filter(|destination| destination.ip.is_ipv6() == ipv6)
        .collect();
    if family_destinations.is_empty() {
        // No steered destination in this family: emit NOTHING rather than an
        // inert chain plus routing, mirroring the host capture path.
        return Vec::new();
    }

    let mark_arg =
        format!("0x{NODE_WAYPOINT_UDP_STEER_MARK:x}/0x{NODE_WAYPOINT_UDP_STEER_MARK_MASK:x}");
    let (ip, local_route) = if ipv6 {
        ("ip -6", "local ::/0 dev lo")
    } else {
        ("ip", "local 0.0.0.0/0 dev lo")
    };
    let priority = NODE_WAYPOINT_UDP_STEER_RULE_PRIORITY;
    let table = NODE_WAYPOINT_UDP_STEER_TABLE;
    let notrack = NODE_WAYPOINT_UDP_STEER_NOTRACK_CHAIN;
    let steer = NODE_WAYPOINT_UDP_STEER_CHAIN;
    let wait = XTABLES_LOCK_WAIT_SECONDS;

    let mut commands = vec![
        // FAIL CLOSED before any rule: this family cannot be installed at all
        // without its own `iptables`/`ip6tables` binary and without iproute2, and
        // a partially installed family is a silent black hole rather than a
        // fail-closed one.
        format!(
            "command -v {binary} >/dev/null 2>&1 || {{ echo \"{binary} is required for \
             NodeWaypoint UDP Service steering of its address family\" >&2; exit 1; }}"
        ),
        "command -v ip >/dev/null 2>&1 || { echo \"iproute2 (ip) is required for NodeWaypoint UDP Service steering\" >&2; exit 1; }"
            .to_string(),
        // STOP MARKING FIRST (see the ordering note above).
        format!("{binary} -t mangle -w {wait} -N {steer} 2>/dev/null || {binary} -t mangle -w {wait} -F {steer}"),
        format!("{binary} -t mangle -w {wait} -F {steer}"),
        // Delete-before-add names Ferrum's exact selector (priority + fwmark
        // mark/mask + table). A priority/table-only delete would also remove a
        // co-resident policy rule at 102/33136 whose mark is not ours.
        ip_delete_best_effort(&format!(
            "{ip} rule del priority {priority} fwmark {mark_arg} lookup {table}"
        )),
        format!("{ip} rule add priority {priority} fwmark {mark_arg} lookup {table}"),
        ip_delete_best_effort(&format!("{ip} route del {local_route} table {table}")),
        format!("{ip} route add {local_route} table {table}"),
        // `raw` conntrack exemption chain.
        format!("{binary} -t raw -w {wait} -N {notrack} 2>/dev/null || {binary} -t raw -w {wait} -F {notrack}"),
        format!("{binary} -t raw -w {wait} -F {notrack}"),
    ];
    for iface in ifaces {
        for destination in &family_destinations {
            commands.push(format!(
                "{binary} -t raw -w {wait} -A {notrack} -i {iface} {} -j CT --notrack",
                destination.selector()
            ));
        }
    }
    commands.push(format!(
        "{binary} -t raw -w {wait} -C PREROUTING -p udp -j {notrack} 2>/dev/null || \
         {binary} -t raw -w {wait} -A PREROUTING -p udp -j {notrack}"
    ));

    // `mangle` mark rules, then the jump. Every destination marked below already
    // has its notrack exemption and its local-delivery route installed above.
    for iface in ifaces {
        for destination in &family_destinations {
            commands.push(format!(
                "{binary} -t mangle -w {wait} -A {steer} -i {iface} {} -j MARK --set-xmark {mark_arg}",
                destination.selector()
            ));
        }
    }
    commands.push(format!(
        "{binary} -t mangle -w {wait} -C PREROUTING -p udp -j {steer} 2>/dev/null || \
         {binary} -t mangle -w {wait} -A PREROUTING -p udp -j {steer}"
    ));

    commands
}

/// Per-family xtables removal of EXACTLY the Ferrum-owned mark and notrack
/// objects, in that order: the mark jump goes first so nothing new can be
/// steered, then the conntrack exemption. Routing is a later, dependent step
/// and is never emitted here — a family whose mark path could not be proven
/// must retain local delivery.
fn node_waypoint_udp_steer_teardown_xtables(binary: &str) -> Vec<String> {
    let notrack = NODE_WAYPOINT_UDP_STEER_NOTRACK_CHAIN;
    let steer = NODE_WAYPOINT_UDP_STEER_CHAIN;
    vec![
        format!("ferrum_delete_xtables_rule {binary} mangle PREROUTING -p udp -j {steer}"),
        format!("ferrum_delete_xtables_chain {binary} mangle {steer}"),
        format!("ferrum_delete_xtables_rule {binary} raw PREROUTING -p udp -j {notrack}"),
        format!("ferrum_delete_xtables_chain {binary} raw {notrack}"),
    ]
}

/// Per-family removal of EXACTLY the Ferrum-owned policy rule and local route.
///
/// Inspect first so only genuine absence is an idempotent success; a failed
/// delete is never reclassified as absent. `ferrum_show_steer_local_routes`
/// classifies iproute2's missing-table dump (`FIB table does not exist`) as
/// that absence: `set -e` plus a raw `ip route show table N` aborts first-pass
/// teardown forever when the Ferrum table has never been created, and the same
/// dump happens after the last local route is deleted because the kernel then
/// drops the table. Permission, lock, and other show failures stay nonzero.
///
/// Every target is named exactly (priority + Ferrum fwmark/mask + table), so
/// this can never disturb the pod-netns TPROXY objects, the tc ingress-redirect
/// routing, or a co-resident CNI's policy routing.
fn node_waypoint_udp_steer_teardown_routing(ipv6: bool) -> Vec<String> {
    let (ip, local_route, cidr) = if ipv6 {
        ("ip -6", "local ::/0 dev lo", "::/0")
    } else {
        ("ip", "local 0.0.0.0/0 dev lo", "0.0.0.0/0")
    };
    let priority = NODE_WAYPOINT_UDP_STEER_RULE_PRIORITY;
    let table = NODE_WAYPOINT_UDP_STEER_TABLE;
    let mark_arg =
        format!("0x{NODE_WAYPOINT_UDP_STEER_MARK:x}/0x{NODE_WAYPOINT_UDP_STEER_MARK_MASK:x}");
    let rule_pattern = format!("fwmark {mark_arg} lookup {table}");
    let rule_pattern_without_mask =
        format!("fwmark 0x{NODE_WAYPOINT_UDP_STEER_MARK:x} lookup {table}");
    // iproute2 commonly renders a zero-prefix as `default` (`local default
    // dev lo scope host`) rather than `0.0.0.0/0` / `::/0`. Matching only the
    // CIDR spelling skips deletion AND the post-delete check, so teardown
    // would return success while the Ferrum-owned route remained. Both
    // spellings are the same prefix; the match still requires this table,
    // `type local`, and `dev lo`.
    let route_case = format!("*'local {cidr} dev lo'*|*'local default dev lo'*");
    let family = if ipv6 { 6 } else { 4 };
    vec![
        format!(
            "ferrum_rule_state=\"$({ip} -o rule show priority {priority})\"\n\
             case \"$ferrum_rule_state\" in\n\
               *'{rule_pattern}'*|*'{rule_pattern_without_mask}'*) {ip} rule del priority {priority} fwmark {mark_arg} lookup {table} ;;\n\
             esac\n\
             ferrum_rule_state=\"$({ip} -o rule show priority {priority})\"\n\
             case \"$ferrum_rule_state\" in\n\
               *'{rule_pattern}'*|*'{rule_pattern_without_mask}'*)\n\
                 echo 'Ferrum NodeWaypoint UDP steering rule remains after deletion' >&2\n\
                 exit 1\n\
                 ;;\n\
             esac"
        ),
        format!(
            "ferrum_show_steer_local_routes {family}\n\
             case \"$ferrum_route_state\" in\n\
               {route_case})\n\
                 {ip} route del {local_route} table {table}\n\
                 ;;\n\
             esac\n\
             ferrum_show_steer_local_routes {family}\n\
             case \"$ferrum_route_state\" in\n\
               {route_case})\n\
                 echo 'Ferrum NodeWaypoint UDP steering route remains after deletion' >&2\n\
                 exit 1\n\
                 ;;\n\
             esac"
        ),
    ]
}

/// One address-family teardown attempt, isolated in a subshell so its failure
/// cannot abort the other family.
///
/// The family body is a simple subshell, never the left-hand side of `&&` /
/// `||` and never an `if` test. Bash and dash disable `set -e` for every
/// command inside a compound command that is in a conditional context,
/// including after an inner `set -e`: `( set -e; ... ) || ferrum_overall=$?`
/// lets an xtables failure fall through into routing, and a later successful
/// command can make the subshell return 0 and erase the failure. Outer
/// `set +e` is required so the subshell's nonzero status does not abort the
/// parent before `$?` is captured and the sibling family runs; inner `set -e`
/// then fail-fasts for real. Routing is emitted only after xtables and after a
/// present `ip` binary, so an unproven mark path retains local delivery.
fn node_waypoint_udp_steer_teardown_family_attempt(binary: &str, ipv6: bool) -> String {
    let family = if ipv6 { "IPv6" } else { "IPv4" };
    let xtables = node_waypoint_udp_steer_teardown_xtables(binary).join("\n");
    let routing = node_waypoint_udp_steer_teardown_routing(ipv6).join("\n");
    format!(
        "# NodeWaypoint UDP steer teardown: {family}\n\
         set +e\n\
         (\n\
         set -e\n\
         command -v {binary} >/dev/null 2>&1 || {{ echo '{binary} is required to reap NodeWaypoint UDP steering' >&2; exit 1; }}\n\
         {xtables}\n\
         command -v ip >/dev/null 2>&1 || {{ echo 'iproute2 (ip) is required to reap NodeWaypoint UDP steering' >&2; exit 1; }}\n\
         {routing}\n\
         )\n\
         ferrum_family_status=$?\n\
         set -e\n\
         if [ \"$ferrum_family_status\" -ne 0 ]; then\n\
           ferrum_overall=$ferrum_family_status\n\
         fi"
    )
}

/// The `set -e` NodeWaypoint UDP Service-steering setup script.
///
/// Returns `Ok(None)` when there is nothing to steer (no enrolled interface or
/// no materialized Service destination) — the caller then runs the teardown so
/// the datapath holds no half-state.
///
/// Every interface name is validated before a command is rendered (it is
/// interpolated into an `iptables -i` argument inside a `sh -c` script and
/// originates from kernel/procfs discovery), and every destination address is
/// re-rendered from a parsed `IpAddr`. A rejected input fails the WHOLE plan
/// rather than being skipped, so a corrupt entry can never yield a
/// partially-scoped ruleset that steers the wrong traffic.
pub fn node_waypoint_udp_steer_setup_script(
    ifaces: &[String],
    destinations: &[NodeWaypointUdpSteerDestination],
) -> Result<Option<String>, String> {
    validate_host_capture_interfaces(ifaces)?;
    if destinations.len() > MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS {
        return Err(format!(
            "NodeWaypoint UDP Service steering is scoped to {} destinations, above the supported \
             maximum of {MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS}",
            destinations.len()
        ));
    }
    for destination in destinations {
        if destination.port == 0 {
            return Err(
                "NodeWaypoint UDP Service steering destination port 0 is not a service \
                        port"
                    .to_string(),
            );
        }
        let inadmissible = match destination.ip {
            std::net::IpAddr::V4(ip) => {
                ip.is_unspecified()
                    || ip.is_loopback()
                    || ip.is_multicast()
                    || ip == std::net::Ipv4Addr::BROADCAST
            }
            std::net::IpAddr::V6(ip) => {
                ip.is_unspecified() || ip.is_loopback() || ip.is_multicast()
            }
        };
        if inadmissible {
            return Err(
                "NodeWaypoint UDP Service steering refuses an unspecified, loopback, multicast, \
                        or IPv4 broadcast destination address: it would steer traffic that never \
                        belonged to a Service"
                    .to_string(),
            );
        }
    }
    if ifaces.is_empty() || destinations.is_empty() {
        return Ok(None);
    }
    let v4 = node_waypoint_udp_steer_commands_for_family("iptables", false, ifaces, destinations);
    let v6 = node_waypoint_udp_steer_commands_for_family("ip6tables", true, ifaces, destinations);
    if v4.is_empty() && v6.is_empty() {
        return Ok(None);
    }
    // A published family is installed COMPLETELY or the whole apply fails.
    // There is deliberately no per-family best-effort arm: a family that is
    // published but not installed is a black hole that looks configured — the
    // reconcile would record the plan as applied and never retry it, while
    // those datagrams silently take the unsteered path. Under `set -e` each
    // family's own `command -v` guard (emitted first, above) exits non-zero, the
    // reconcile tears every Ferrum-owned object down, and the next reconcile
    // retries the whole plan. Teardown attempts families independently, so if
    // family B's tool is absent after family A partly installed, family A can
    // still be reaped; overall teardown stays unproven until every family is.

    let mut chunks = Vec::new();
    if !v4.is_empty() {
        chunks.push(v4.join("\n"));
    }
    if !v6.is_empty() {
        chunks.push(v6.join("\n"));
    }
    Ok(Some(format!("set -e\n{}", chunks.join("\n"))))
}

/// The NodeWaypoint UDP Service-steering teardown script.
///
/// Exact-name and idempotent, but strict: a genuinely absent Ferrum-owned
/// object succeeds, while inspection, permission, resource, delete, and
/// post-delete verification failures stay nonzero. IPv4 and IPv6 are attempted
/// independently because a predecessor may have left state in a family whose
/// tool is missing on this generation: a broken `ip6tables` must not prevent
/// live IPv4 cleanup, and vice versa. Overall success still requires every
/// family to be proven, so a missing family tool or any inspection/delete/
/// verification failure keeps the script nonzero and must never claim `reaped`
/// or publish a replacement. Within a family, mark → notrack must be proven
/// before local routing is removed (inert leftover routing is safer than
/// marked traffic without local delivery). If shared `ip` is unavailable,
/// every safe xtables cleanup is still attempted and routing is retained.
/// Each family runs in a simple subshell with inner errexit; the parent
/// captures that exact status on the next line without wrapping the subshell
/// in `if`/`&&`/`||`, then restores outer errexit and still attempts the
/// sibling family.
///
/// Jump deletion probes the user-chain with `-S` before `-C` of a jump into
/// it. nft-backed iptables returns 2 for `-C ... -j <missing-chain>` (issue
/// #2084); treating that as a resource error left first-pass teardown failing
/// forever and blocked every subsequent setup. `-S` returns 1 for an absent
/// chain on both legacy and nft backends, so absence stays portable without
/// accepting lock or permission failures as success. The `-S` status is
/// captured from a non-inverted `if`/`else`: POSIX `if ! cmd; then status=$?`
/// records 0 (the inverted compound status) and would treat lock and
/// permission failures as absence.
///
/// Route inspection has the same first-pass trap: iproute2's
/// `ip route show table N type local` exits 2 with `FIB table does not exist`
/// when table `N` has never been created (and again after the last local route
/// is deleted, because the kernel then drops the table). That message is
/// genuine absence. Other show failures — permission, dump errors that are
/// not that message — stay nonzero. Status is captured with an uninverted
/// `|| ferrum_status=$?` so `set -e` cannot abort before the classification.
pub fn node_waypoint_udp_steer_teardown_script() -> String {
    let helpers = format!(
        "set -e\n\
         ferrum_delete_xtables_rule() {{\n\
           ferrum_binary=\"$1\"; ferrum_table=\"$2\"; shift 2\n\
           ferrum_jump_target=\"\"; ferrum_prev=\"\"\n\
           for ferrum_arg in \"$@\"; do\n\
             if [ \"$ferrum_prev\" = \"-j\" ]; then\n\
               ferrum_jump_target=\"$ferrum_arg\"\n\
             fi\n\
             ferrum_prev=\"$ferrum_arg\"\n\
           done\n\
           if [ -n \"$ferrum_jump_target\" ]; then\n\
             if \"$ferrum_binary\" -t \"$ferrum_table\" -w {XTABLES_LOCK_WAIT_SECONDS} -S \"$ferrum_jump_target\" >/dev/null 2>&1; then\n\
               ferrum_status=0\n\
             else\n\
               ferrum_status=$?\n\
               if [ \"$ferrum_status\" -ne 1 ]; then\n\
                 echo 'Ferrum NodeWaypoint UDP steering jump-target chain inspection failed' >&2\n\
                 return \"$ferrum_status\"\n\
               fi\n\
               return 0\n\
             fi\n\
           fi\n\
           if \"$ferrum_binary\" -t \"$ferrum_table\" -w {XTABLES_LOCK_WAIT_SECONDS} -C \"$@\" >/dev/null 2>&1; then\n\
             \"$ferrum_binary\" -t \"$ferrum_table\" -w {XTABLES_LOCK_WAIT_SECONDS} -D \"$@\"\n\
           else\n\
             ferrum_status=$?\n\
             if [ \"$ferrum_status\" -ne 1 ]; then\n\
               echo 'Ferrum NodeWaypoint UDP steering rule inspection failed' >&2\n\
               return \"$ferrum_status\"\n\
             fi\n\
           fi\n\
           if \"$ferrum_binary\" -t \"$ferrum_table\" -w {XTABLES_LOCK_WAIT_SECONDS} -C \"$@\" >/dev/null 2>&1; then\n\
             echo 'Ferrum NodeWaypoint UDP steering jump remains after deletion' >&2\n\
             return 1\n\
           else\n\
             ferrum_status=$?\n\
             if [ \"$ferrum_status\" -ne 1 ]; then\n\
               echo 'Ferrum NodeWaypoint UDP steering rule verification failed' >&2\n\
               return \"$ferrum_status\"\n\
             fi\n\
           fi\n\
         }}\n\
         ferrum_delete_xtables_chain() {{\n\
           ferrum_binary=\"$1\"; ferrum_table=\"$2\"; ferrum_chain=\"$3\"\n\
           if \"$ferrum_binary\" -t \"$ferrum_table\" -w {XTABLES_LOCK_WAIT_SECONDS} -S \"$ferrum_chain\" >/dev/null 2>&1; then\n\
             \"$ferrum_binary\" -t \"$ferrum_table\" -w {XTABLES_LOCK_WAIT_SECONDS} -F \"$ferrum_chain\"\n\
             \"$ferrum_binary\" -t \"$ferrum_table\" -w {XTABLES_LOCK_WAIT_SECONDS} -X \"$ferrum_chain\"\n\
           else\n\
             ferrum_status=$?\n\
             if [ \"$ferrum_status\" -ne 1 ]; then\n\
               echo 'Ferrum NodeWaypoint UDP steering chain inspection failed' >&2\n\
               return \"$ferrum_status\"\n\
             fi\n\
           fi\n\
           if \"$ferrum_binary\" -t \"$ferrum_table\" -w {XTABLES_LOCK_WAIT_SECONDS} -S \"$ferrum_chain\" >/dev/null 2>&1; then\n\
             echo 'Ferrum NodeWaypoint UDP steering chain remains after deletion' >&2\n\
             return 1\n\
           else\n\
             ferrum_status=$?\n\
             if [ \"$ferrum_status\" -ne 1 ]; then\n\
               echo 'Ferrum NodeWaypoint UDP steering chain verification failed' >&2\n\
               return \"$ferrum_status\"\n\
             fi\n\
           fi\n\
         }}\n\
         ferrum_show_steer_local_routes() {{\n\
           ferrum_family=\"$1\"\n\
           ferrum_status=0\n\
           if [ \"$ferrum_family\" = 6 ]; then\n\
             ferrum_show=\"$(ip -6 route show table {NODE_WAYPOINT_UDP_STEER_TABLE} type local 2>&1)\" || ferrum_status=$?\n\
           else\n\
             ferrum_show=\"$(ip route show table {NODE_WAYPOINT_UDP_STEER_TABLE} type local 2>&1)\" || ferrum_status=$?\n\
           fi\n\
           if [ \"$ferrum_status\" -ne 0 ]; then\n\
             case \"$ferrum_show\" in\n\
               *'FIB table does not exist'*)\n\
                 ferrum_route_state=\"\"\n\
                 return 0\n\
                 ;;\n\
               *)\n\
                 echo 'Ferrum NodeWaypoint UDP steering route inspection failed' >&2\n\
                 printf '%s\\n' \"$ferrum_show\" >&2\n\
                 return \"$ferrum_status\"\n\
                 ;;\n\
             esac\n\
           fi\n\
           ferrum_route_state=\"$ferrum_show\"\n\
         }}"
    );
    format!(
        "{helpers}\n\
         ferrum_overall=0\n\
         {}\n\
         {}\n\
         exit \"$ferrum_overall\"",
        node_waypoint_udp_steer_teardown_family_attempt("iptables", false),
        node_waypoint_udp_steer_teardown_family_attempt("ip6tables", true),
    )
}

/// Istio-compatible `includeOutboundPorts` annotation. The injector and the
/// node-agent eBPF backend both read this key — keep the spelling exactly
/// in sync with Istio so existing operator annotations apply unchanged.
pub const ISTIO_INCLUDE_OUTBOUND_PORTS_ANNOTATION: &str =
    "traffic.sidecar.istio.io/includeOutboundPorts";
/// Ferrum-native alias for [`ISTIO_INCLUDE_OUTBOUND_PORTS_ANNOTATION`]. Both
/// keys are read; values from the two annotations merge per
/// [`include_outbound_ports_from_annotations`].
pub const FERRUM_INCLUDE_OUTBOUND_PORTS_ANNOTATION: &str = "ferrum.io/includeOutboundPorts";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    Explicit,
    Iptables,
    Ebpf,
}

impl CaptureMode {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.to_ascii_lowercase().as_str() {
            "explicit" => Ok(Self::Explicit),
            "iptables" => Ok(Self::Iptables),
            "ebpf" => Ok(Self::Ebpf),
            other => Err(format!(
                "Invalid FERRUM_MESH_CAPTURE_MODE {}. Expected: explicit, iptables, or ebpf",
                quoted_config_value("FERRUM_MESH_CAPTURE_MODE", other)
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ip6TablesMode {
    Auto,
    Required,
    Disabled,
}

impl Ip6TablesMode {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "true" | "required" => Ok(Self::Required),
            "false" | "disabled" => Ok(Self::Disabled),
            other => Err(format!(
                "Invalid FERRUM_MESH_IP6TABLES_ENABLED {}. Expected: auto, true, or false",
                quoted_config_value("FERRUM_MESH_IP6TABLES_ENABLED", other)
            )),
        }
    }

    pub fn as_env_value(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Required => "true",
            Self::Disabled => "false",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfig {
    pub mode: CaptureMode,
    /// Non-zero proxy UID to exempt; `None` disables the owner exemption.
    pub proxy_uid: Option<u32>,
    pub inbound_port: u16,
    pub outbound_port: u16,
    /// Whether outbound capture is enabled. The node-agent sets this `false`
    /// when `FERRUM_MESH_OUTBOUND_LISTEN_ADDR`'s port is `0` (the mesh proxy
    /// disables its outbound listener), so it neither attaches the connect4/
    /// connect6 redirect nor publishes the in-netns registry — otherwise a
    /// captured pod's egress would be rewritten to a loopback port with no
    /// listener. Inbound capture is unaffected.
    pub outbound_capture_enabled: bool,
    pub include_cidrs: Vec<String>,
    /// True when `include_cidrs` came from operator or pod configuration rather
    /// than the implicit catch-all default. When includeOutboundPorts is set,
    /// the implicit default must not swallow all ports before port rules match.
    pub include_cidrs_explicit: bool,
    /// True when includeOutboundPorts was explicitly set to `*`. This must be
    /// distinct from an empty `include_outbound_ports`, which means the
    /// annotation was absent or empty and CIDR includes should drive capture.
    pub include_all_outbound_ports: bool,
    pub include_outbound_ports: Vec<u16>,
    pub exclude_cidrs: Vec<String>,
    pub exclude_ports: Vec<u16>,
    /// True when `exclude_ports` came from operator configuration rather than the
    /// implicit sidecar defaults. Ambient per-pod UDP capture runs inside workload
    /// netns with no co-located sidecar, so it must drop the implicit sidecar port
    /// excludes while preserving explicit operator exclusions.
    pub exclude_ports_explicit: bool,
    /// TCP destination ports excluded from the inbound capture chain. Each
    /// listed port emits a `RETURN` rule placed BEFORE the inbound REDIRECT,
    /// so traffic to the port bypasses the mesh sidecar entirely.
    pub exclude_inbound_ports: Vec<u16>,
    /// Additional TCP-only destination ports excluded from inbound capture.
    /// These are not mirrored into the UDP TPROXY chain.
    pub exclude_inbound_tcp_ports: Vec<u16>,
    pub ip6tables_mode: Ip6TablesMode,
    /// Whether UDP TPROXY capture rules are emitted (F3 §3.3 Stage 2). Default
    /// `false`: UDP cannot use the TCP REDIRECT model (REDIRECT rewrites the
    /// destination and offers no per-datagram recoverable original address), so
    /// captured UDP uses TPROXY in the `mangle` table, which delivers the
    /// datagram WITHOUT rewriting its destination (recovered per-datagram from
    /// the `IP_RECVORIGDSTADDR` cmsg by the Stage 3 listener). This stage emits
    /// rules ONLY; the consuming UDP listener arrives in Stage 3, so leaving
    /// this off keeps an upgraded injector from redirecting UDP into a void.
    pub udp_capture_enabled: bool,
    /// UDP TPROXY listener port the captured datagrams are delivered to. Distinct
    /// from [`Self::outbound_port`] (the TCP REDIRECT target) because UDP+TCP
    /// cannot share one listener socket.
    pub udp_outbound_port: u16,
    /// Firewall mark stamped on TPROXY'd UDP datagrams; the policy routing rule
    /// matches it to steer them to the local-delivery table. See
    /// [`DEFAULT_TPROXY_MARK`] for the collision analysis.
    pub tproxy_mark: u32,
    /// `true` when these rules are applied in the HOST network namespace (the
    /// node-agent DaemonSet, `hostNetwork: true`), `false` for the injector init
    /// container (the POD's own network namespace).
    ///
    /// This gates ONLY the pod-netns UDP TPROXY direction split. The TCP path
    /// separates inbound vs outbound by netfilter HOOK (`nat PREROUTING` vs
    /// `nat OUTPUT`), which is netns-agnostic, so it is unaffected. The pod-netns
    /// UDP TPROXY path cannot use that trick (TPROXY is `PREROUTING`-only) so it
    /// splits direction by destination ADDRESS TYPE (`-m addrtype --dst-type
    /// LOCAL`). That discriminator is only correct in the POD netns, where the
    /// pod's own IP is `LOCAL`: in the HOST netns pod IPs are FORWARDED (not
    /// `LOCAL`), so inbound UDP to a pod would match the OUTBOUND chain's
    /// `! --dst-type LOCAL` discriminator and be mis-captured. So the pod-netns
    /// rule generator emits NO UDP TPROXY rules when this flag is set. See
    /// [`udp_tproxy_commands_for_family`].
    ///
    /// The **host-network UDP capture path** (issue #3288) is a SEPARATE rule
    /// generator ([`IptablesPlan::host_udp_setup_script`]) that does not use an
    /// `addrtype` direction split at all: it discriminates by INGRESS INTERFACE
    /// (`-i <host-side pod interface>` in `mangle PREROUTING`), which is exact in
    /// the host netns — a pod's egress is the only traffic that enters the host
    /// namespace on that pod's own interface. Setting `host_netns` therefore does
    /// NOT disable host UDP capture; it selects which generator is valid.
    pub host_netns: bool,
}

impl CaptureConfig {
    /// Whether the Ambient UDP producer's per-pod setup will FATALLY require
    /// `ip6tables`: `FERRUM_MESH_IP6TABLES_ENABLED=required` AND at least one IPv6
    /// UDP include/exclude CIDR, so `udp_iptables_script` emits its required-mode
    /// `ip6tables` preflight (which `exit 1`s the per-pod script when `ip6tables`
    /// is missing). The producer's STARTUP preflight (`preflight_capture_tools`)
    /// consults this to fail fast when the runtime image lacks `ip6tables`, rather
    /// than letting every per-pod setup fail and retry forever (codex). The exact
    /// condition mirrors `udp_only_for_config`'s v6-command gate.
    pub(crate) fn udp_ipv6_capture_required(&self) -> bool {
        self.udp_capture_enabled
            && self.ip6tables_mode == Ip6TablesMode::Required
            && self
                .include_cidrs
                .iter()
                .chain(self.exclude_cidrs.iter())
                .any(|cidr| cidr_family(cidr) == Some(CidrFamily::V6))
    }

    /// Build an `Explicit`-mode capture config with the implicit `0.0.0.0/0`
    /// include CIDR default.
    ///
    /// `include_cidrs_explicit` is set to `false` here because the included
    /// `0.0.0.0/0` is the implicit catch-all default, not an operator-supplied
    /// value. Callers populating `include_cidrs` manually (e.g., tests) that
    /// want the operator-supplied-`0.0.0.0/0` semantics — where the catch-all
    /// is treated as an explicit choice rather than swallowed by
    /// `includeOutboundPorts` narrowing — should also set
    /// `include_cidrs_explicit: true` after construction.
    pub fn explicit(inbound_port: u16, outbound_port: u16) -> Self {
        Self {
            mode: CaptureMode::Explicit,
            proxy_uid: Some(DEFAULT_PROXY_UID),
            inbound_port,
            outbound_port,
            outbound_capture_enabled: true,
            include_cidrs: vec!["0.0.0.0/0".to_string()],
            include_cidrs_explicit: false,
            include_all_outbound_ports: false,
            include_outbound_ports: Vec::new(),
            exclude_cidrs: Vec::new(),
            exclude_ports: Vec::new(),
            exclude_ports_explicit: false,
            exclude_inbound_ports: Vec::new(),
            exclude_inbound_tcp_ports: Vec::new(),
            ip6tables_mode: Ip6TablesMode::Auto,
            udp_capture_enabled: false,
            udp_outbound_port: DEFAULT_UDP_OUTBOUND_PORT,
            tproxy_mark: DEFAULT_TPROXY_MARK,
            // The injector (pod netns) is the canonical `explicit`-config caller;
            // the node-agent (host netns) sets this `true` after `from_env`.
            host_netns: false,
        }
    }

    pub fn from_env() -> Result<Self, String> {
        let mode = CaptureMode::parse(
            &resolve_ferrum_var("FERRUM_MESH_CAPTURE_MODE")
                .unwrap_or_else(|| "explicit".to_string()),
        )?;
        let proxy_uid = match resolve_ferrum_var("FERRUM_MESH_PROXY_UID") {
            Some(raw) => Some(parse_proxy_uid(&raw)?),
            None => Some(DEFAULT_PROXY_UID),
        };
        let include_cidrs_raw = resolve_ferrum_var("FERRUM_MESH_CAPTURE_INCLUDE_CIDRS");
        let include_cidrs_explicit = include_cidrs_raw.is_some();
        let include_cidrs =
            parse_cidr_env(&include_cidrs_raw.unwrap_or_else(|| "0.0.0.0/0".to_string()));
        validate_cidr_list(&include_cidrs)?;
        let exclude_cidrs = parse_cidr_env(
            &resolve_ferrum_var("FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS").unwrap_or_default(),
        );
        if !exclude_cidrs.is_empty() {
            validate_cidr_list(&exclude_cidrs)?;
        }
        let exclude_ports_raw = resolve_ferrum_var("FERRUM_MESH_CAPTURE_EXCLUDE_PORTS");
        let exclude_ports_explicit = exclude_ports_raw.is_some();
        let exclude_ports = parse_port_list(
            &exclude_ports_raw.unwrap_or_else(|| "15001,15006,15008,15020".to_string()),
        )?;
        let exclude_inbound_ports = parse_port_list(
            &resolve_ferrum_var("FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS").unwrap_or_default(),
        )?;
        let ip6tables_mode = Ip6TablesMode::parse(
            &resolve_ferrum_var("FERRUM_MESH_IP6TABLES_ENABLED")
                .unwrap_or_else(|| "auto".to_string()),
        )?;
        let UdpCaptureSettings {
            udp_capture_enabled,
            udp_outbound_port,
            tproxy_mark,
            // Placement (pod netns vs host netns) is decided by the mesh proxy's
            // Ambient wiring, not by this scope config.
            udp_host_netns_enabled: _,
        } = udp_capture_settings_from_env()?;
        Ok(Self {
            mode,
            proxy_uid,
            inbound_port: 15006,
            outbound_port: 15001,
            outbound_capture_enabled: true,
            include_cidrs,
            include_cidrs_explicit,
            include_all_outbound_ports: false,
            include_outbound_ports: Vec::new(),
            exclude_cidrs,
            exclude_ports,
            exclude_ports_explicit,
            exclude_inbound_ports,
            exclude_inbound_tcp_ports: Vec::new(),
            ip6tables_mode,
            udp_capture_enabled,
            udp_outbound_port,
            tproxy_mark,
            // `from_env` is the node-agent's capture-config source. The node-agent
            // runs `hostNetwork: true`, but the host-netns flag is set explicitly
            // by `NodeAgentConfig::from_env_config` (not inferred here) so a test
            // or future non-host-netns caller of `from_env` is not forced into the
            // host-netns UDP suppression. Default `false`; the node-agent flips it.
            host_netns: false,
        })
    }

    /// Validate direct construction as well as environment-derived capture settings.
    pub fn validate_proxy_uid(&self) -> Result<(), String> {
        if let Some(uid) = self.proxy_uid {
            validate_proxy_uid(uid)?;
        }
        Ok(())
    }

    pub fn ensure_exclude_port(&mut self, port: u16) {
        if !self.exclude_ports.contains(&port) {
            self.exclude_ports.push(port);
        }
        self.exclude_ports_explicit = true;
    }

    pub fn clear_implicit_exclude_ports(&mut self) {
        if !self.exclude_ports_explicit {
            self.exclude_ports.clear();
        }
    }
}

/// UDP TPROXY capture settings parsed from the environment (F3 §3.3 Stage 2).
/// Shared by [`CaptureConfig::from_env`] (node-agent capture fallback) and the
/// injector so the three vars are parsed in exactly one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpCaptureSettings {
    pub udp_capture_enabled: bool,
    pub udp_outbound_port: u16,
    pub tproxy_mark: u32,
    /// Whether the Ambient mesh proxy captures UDP from its OWN (host) network
    /// namespace, using host-side per-pod interface scoping, instead of entering
    /// each enrolled pod's netns (issue #3288). Default `false`: the per-pod-netns
    /// producer stays the default because it needs no interface attribution, and
    /// the host path is only correct on a CNI that gives each pod its own
    /// host-side interface. Requires `udp_capture_enabled`.
    pub udp_host_netns_enabled: bool,
}

/// Parse `FERRUM_MESH_CAPTURE_UDP_ENABLED` (default `false`),
/// `FERRUM_MESH_CAPTURE_UDP_PORT` (default [`DEFAULT_UDP_OUTBOUND_PORT`]),
/// `FERRUM_MESH_TPROXY_MARK` (default [`DEFAULT_TPROXY_MARK`]), and
/// `FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED` (default `false`).
///
/// Fails closed on an inconsistent combination: enabling the host-netns path
/// without enabling UDP capture is a configuration error, not a silent no-op —
/// an operator who set only the host switch would otherwise get NO capture while
/// believing UDP was covered.
pub fn udp_capture_settings_from_env() -> Result<UdpCaptureSettings, String> {
    let udp_capture_enabled = parse_bool_env(
        resolve_ferrum_var("FERRUM_MESH_CAPTURE_UDP_ENABLED").as_deref(),
        "FERRUM_MESH_CAPTURE_UDP_ENABLED",
    )?;
    let udp_outbound_port = match resolve_ferrum_var("FERRUM_MESH_CAPTURE_UDP_PORT") {
        Some(raw) => parse_single_port(&raw, "FERRUM_MESH_CAPTURE_UDP_PORT")?,
        None => DEFAULT_UDP_OUTBOUND_PORT,
    };
    let tproxy_mark = match resolve_ferrum_var("FERRUM_MESH_TPROXY_MARK") {
        Some(raw) => parse_tproxy_mark(&raw)?,
        None => DEFAULT_TPROXY_MARK,
    };
    let udp_host_netns_enabled = parse_bool_env(
        resolve_ferrum_var("FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED").as_deref(),
        "FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED",
    )?;
    if udp_host_netns_enabled && !udp_capture_enabled {
        return Err("FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED=true requires \
             FERRUM_MESH_CAPTURE_UDP_ENABLED=true (the host-network capture path is a \
             placement choice for UDP capture, not a separate feature switch)"
            .to_string());
    }
    Ok(UdpCaptureSettings {
        udp_capture_enabled,
        udp_outbound_port,
        tproxy_mark,
        udp_host_netns_enabled,
    })
}

/// Whether the mesh data plane must serve IPv6 CAPTURED traffic on this
/// workload — i.e. whether `ip6tables` capture rules are (or will be) installed
/// in this network namespace (issue #4271).
///
/// This is the runtime half of a producer/consumer pair. The rule PRODUCER is
/// the injector's init container, which emits `ip6tables` REDIRECTs when
/// `FERRUM_MESH_IP6TABLES_ENABLED` is not `disabled` AND at least one
/// include/exclude CIDR is IPv6 — exactly [`IptablesPlan::for_config`]'s v6
/// gate. The CONSUMER is the sidecar's TCP capture listener plan, which must
/// bind a socket able to accept the family those rules divert, or the captured
/// IPv6 connections land on a port with no listener and are black-holed with
/// `ECONNREFUSED`.
///
/// Resolution order:
///
/// 1. `FERRUM_MESH_CAPTURE_IPV6_ENABLED`, the explicit operator/injector signal.
///    The injector sets it to `true` on the sidecar container whenever the init
///    container's rendered plan actually contains `ip6tables` commands. An
///    explicit `false` is rejected when the local rule inputs independently
///    require IPv6; accepting that contradiction would recreate the silent
///    listener/rule-family black hole this signal exists to prevent.
/// 2. Otherwise the same derivation applied to whatever capture scope env this
///    process can see, so a hand-rolled (non-injector) sidecar that carries the
///    capture CIDRs still plans the right listeners.
///
/// Errors are the ordinary malformed-env errors of the underlying parsers; the
/// serving path turns them into a startup failure rather than guessing.
pub fn capture_ipv6_enabled_from_env() -> Result<bool, String> {
    if let Some(raw) = resolve_ferrum_var("FERRUM_MESH_CAPTURE_IPV6_ENABLED")
        && !raw.trim().is_empty()
    {
        let explicit = parse_bool_env(Some(raw.as_str()), "FERRUM_MESH_CAPTURE_IPV6_ENABLED")?;
        if explicit {
            return Ok(true);
        }
        if capture_ipv6_derived_from_env()? {
            return Err(
                "FERRUM_MESH_CAPTURE_IPV6_ENABLED=false contradicts the configured IPv6 capture \
                 rule inputs: FERRUM_MESH_IP6TABLES_ENABLED is not false and an include/exclude \
                 CIDR is IPv6. Disable the IPv6 rule producer with \
                 FERRUM_MESH_IP6TABLES_ENABLED=false (or remove the IPv6 CIDRs) instead of \
                 leaving ip6tables REDIRECTs without a listener"
                    .to_string(),
            );
        }
        return Ok(false);
    }
    capture_ipv6_derived_from_env()
}

fn capture_ipv6_derived_from_env() -> Result<bool, String> {
    let ip6tables_mode = Ip6TablesMode::parse(
        &resolve_ferrum_var("FERRUM_MESH_IP6TABLES_ENABLED").unwrap_or_else(|| "auto".to_string()),
    )?;
    if ip6tables_mode == Ip6TablesMode::Disabled {
        return Ok(false);
    }
    let include_cidrs = parse_cidr_env(
        &resolve_ferrum_var("FERRUM_MESH_CAPTURE_INCLUDE_CIDRS").unwrap_or_default(),
    );
    if !include_cidrs.is_empty() {
        validate_cidr_list(&include_cidrs)
            .map_err(|e| format!("FERRUM_MESH_CAPTURE_INCLUDE_CIDRS: {e}"))?;
    }
    let exclude_cidrs = parse_cidr_env(
        &resolve_ferrum_var("FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS").unwrap_or_default(),
    );
    if !exclude_cidrs.is_empty() {
        validate_cidr_list(&exclude_cidrs)
            .map_err(|e| format!("FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS: {e}"))?;
    }
    Ok(include_cidrs
        .iter()
        .chain(exclude_cidrs.iter())
        .any(|cidr| cidr_family(cidr) == Some(CidrFamily::V6)))
}

/// Validate a host-side interface name before it is interpolated into an
/// `iptables -i <iface>` argument inside a `sh -c` script.
///
/// The name reaches this function from kernel/procfs discovery driven by a
/// node-agent-published registry file, i.e. from OUTSIDE this process, so it is
/// treated as hostile input at the boundary:
///
/// * Length is bounded by Linux `IFNAMSIZ` (15 usable characters). A longer name
///   cannot name a real interface and would only widen the script.
/// * The character set is restricted to `[A-Za-z0-9._-]`. This rejects every
///   shell metacharacter (`;`, `&`, `|`, `$`, backticks, quotes, whitespace,
///   newlines), so a crafted registry entry cannot inject a command into the
///   generated script.
/// * A leading `-` is rejected so a name can never be parsed as an `iptables`
///   option, and `.` / `..` are rejected outright.
/// * `+` is rejected even though the character is otherwise harmless: in an
///   `iptables -i` argument a trailing `+` is a PREFIX WILDCARD (`veth+` matches
///   every `veth*` interface). Accepting it would silently widen capture from one
///   enrolled pod to every interface sharing a prefix — the exact wildcard
///   overreach this path must not have.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn validate_host_capture_interface(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("host capture interface name must not be empty".to_string());
    }
    if name.len() > MAX_INTERFACE_NAME_LEN {
        return Err(format!(
            "host capture interface name is longer than the {MAX_INTERFACE_NAME_LEN}-character \
             kernel limit"
        ));
    }
    if name == "." || name == ".." {
        return Err("host capture interface name must not be `.` or `..`".to_string());
    }
    if name.starts_with('-') {
        return Err("host capture interface name must not start with `-`".to_string());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(
            "host capture interface name must contain only ASCII letters, digits, `.`, `_`, \
             or `-` (a `+` suffix would be an iptables prefix wildcard)"
                .to_string(),
        );
    }
    Ok(())
}

/// Validate an entire host capture interface set, rejecting duplicates and an
/// over-large set. Duplicates would emit duplicate rules that teardown reaps only
/// once, so they are refused rather than deduplicated silently.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn validate_host_capture_interfaces(ifaces: &[String]) -> Result<(), String> {
    if ifaces.len() > MAX_HOST_UDP_CAPTURE_INTERFACES {
        return Err(format!(
            "host UDP capture is scoped to {} interfaces, above the supported maximum of \
             {MAX_HOST_UDP_CAPTURE_INTERFACES}",
            ifaces.len()
        ));
    }
    for (index, iface) in ifaces.iter().enumerate() {
        validate_host_capture_interface(iface)?;
        if ifaces[..index].iter().any(|earlier| earlier == iface) {
            return Err("host UDP capture interface set contains a duplicate entry".to_string());
        }
    }
    Ok(())
}

fn parse_cidr_env(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn parse_port_list(raw: &str) -> Result<Vec<u16>, String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            let port = s
                .parse::<u16>()
                .map_err(|_| format!("Invalid port {s:?} in capture exclude ports"))?;
            if port == 0 {
                return Err(format!(
                    "Invalid port {s:?} in capture exclude ports: port must be 1-65535"
                ));
            }
            Ok(port)
        })
        .collect()
}

/// Pod-level `includeOutboundPorts` annotation parsed once, shared by the
/// injector (writes iptables rules in the init container) and the node-agent
/// eBPF capture path (writes a per-cgroup BPF map entry). Keeping a single
/// parser prevents the two surfaces from drifting apart on edge cases
/// (wildcard handling, duplicates, malformed tokens).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IncludeOutboundPorts {
    /// `true` when the annotation was `*` — capture all outbound ports.
    pub all_ports: bool,
    /// Explicit destination ports to capture. Sorted, deduplicated. Empty
    /// when `all_ports == true`.
    pub ports: Vec<u16>,
}

impl IncludeOutboundPorts {
    /// Returns `true` when the annotation was absent / blank (capture
    /// driven purely by include CIDRs).
    pub fn is_absent(&self) -> bool {
        !self.all_ports && self.ports.is_empty()
    }
}

/// One annotation's parse result, before two annotations get merged together.
/// Kept private so the merge contract stays in
/// [`include_outbound_ports_from_annotations`].
#[derive(Debug, PartialEq, Eq)]
pub enum ParsedIncludePorts {
    Absent,
    All,
    Ports(Vec<u16>),
}

/// Parse a single `includeOutboundPorts` annotation value.
///
/// Returns:
/// - `Absent` for `None`, empty string, or whitespace-only string.
/// - `All` when the value is `*`.
/// - `Ports(_)` for a comma-separated list of 1..=65535 integers.
///
/// Errors on: mixing `*` with explicit ports, repeated `*`, non-numeric
/// tokens, port `0`, port outside `u16`.
pub fn parse_include_port_list(raw: Option<&str>) -> Result<ParsedIncludePorts, String> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(ParsedIncludePorts::Absent);
    };

    let mut ports = Vec::new();
    let mut saw_wildcard = false;
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        if token == "*" {
            if saw_wildcard || !ports.is_empty() {
                return Err("wildcard `*` must be the only includeOutboundPorts token".to_string());
            }
            saw_wildcard = true;
            continue;
        }
        if saw_wildcard {
            return Err("wildcard `*` must be the only includeOutboundPorts token".to_string());
        }
        let port = token
            .parse::<u16>()
            .map_err(|e| format!("port {token:?}: {e}"))?;
        if port == 0 {
            return Err(format!("port {token:?}: port must be 1-65535"));
        }
        ports.push(port);
    }
    if saw_wildcard {
        return Ok(ParsedIncludePorts::All);
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ParsedIncludePorts::Ports(ports))
}

/// Merge the two parallel `includeOutboundPorts` annotations
/// (Istio + Ferrum-native alias) into a single [`IncludeOutboundPorts`].
///
/// `annotations` is an iterator over `(annotation_key, raw_value)` pairs.
/// Callers pass the keys they want to consider, in priority order — typically
/// Istio first, then Ferrum's alias. The iterator should yield each key at
/// most once; duplicates are tolerated but only the first non-absent entry
/// per key sets the wildcard / explicit-ports keys for error messages.
///
/// Wildcard semantics: once any annotation says `*` no explicit ports may be
/// added from another annotation, and vice-versa. This is the same rule
/// `injector::include_outbound_ports_for_pod` previously enforced inline.
pub fn include_outbound_ports_from_annotations<'a, I>(
    annotations: I,
) -> Result<IncludeOutboundPorts, String>
where
    I: IntoIterator<Item = (&'a str, Option<&'a str>)>,
{
    let mut ports: Vec<u16> = Vec::new();
    let mut saw_wildcard = false;
    let mut wildcard_key: Option<&str> = None;
    let mut explicit_ports_key: Option<&str> = None;
    // Only the two fixed schema keys are safe to retain as labels. This public
    // helper also accepts other keys, which must stay inside escaped quotes.
    let diagnostic_key = |key: &str| match key {
        ISTIO_INCLUDE_OUTBOUND_PORTS_ANNOTATION | FERRUM_INCLUDE_OUTBOUND_PORTS_ANNOTATION => {
            format!("`{key}`")
        }
        _ => format!("{key:?}"),
    };
    for (key, raw) in annotations {
        match parse_include_port_list(raw)
            .map_err(|e| format!("invalid {}: {e}", diagnostic_key(key)))?
        {
            ParsedIncludePorts::Absent => {}
            ParsedIncludePorts::All => {
                if !ports.is_empty() {
                    let explicit_key = explicit_ports_key
                        .map(diagnostic_key)
                        .unwrap_or_else(|| "another includeOutboundPorts annotation".to_string());
                    return Err(format!(
                        "invalid {}: wildcard `*` cannot be combined with explicit includeOutboundPorts in {explicit_key}",
                        diagnostic_key(key)
                    ));
                }
                saw_wildcard = true;
                wildcard_key.get_or_insert(key);
            }
            ParsedIncludePorts::Ports(annotation_ports) => {
                if saw_wildcard && !annotation_ports.is_empty() {
                    let wildcard_key = wildcard_key
                        .map(diagnostic_key)
                        .unwrap_or_else(|| "another includeOutboundPorts annotation".to_string());
                    return Err(format!(
                        "invalid {}: explicit includeOutboundPorts cannot be combined with wildcard `*` in {wildcard_key}",
                        diagnostic_key(key)
                    ));
                }
                if !annotation_ports.is_empty() {
                    explicit_ports_key.get_or_insert(key);
                }
                ports.extend(annotation_ports);
            }
        }
    }
    if saw_wildcard {
        return Ok(IncludeOutboundPorts {
            all_ports: true,
            ports: Vec::new(),
        });
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(IncludeOutboundPorts {
        all_ports: false,
        ports,
    })
}

/// Parse a boolean capture env var. Absent / blank defaults to `false`. Accepts
/// the repo-wide boolean env forms (`EnvValue for bool` in
/// `config::env_config_macro`): case-insensitive `true`/`false` plus `1`/`0`.
/// Rust's `bool::from_str` (used previously) rejected `1`/`0`/`TRUE`, diverging
/// from every sibling `FERRUM_MESH_*` bool env (codex r3).
fn parse_bool_env(raw: Option<&str>, var: &str) -> Result<bool, String> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(false),
        Some(value) => match value.to_ascii_lowercase().as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            _ => Err(format!(
                "Invalid {var} {}. Expected true, false, 1, or 0",
                quoted_config_value(var, value)
            )),
        },
    }
}

/// Parse a single 1..=65535 destination port from an env var.
fn parse_single_port(raw: &str, var: &str) -> Result<u16, String> {
    let trimmed = raw.trim();
    let port = trimmed.parse::<u16>().map_err(|_| {
        format!(
            "Invalid {var} {}. Expected a port in 1-65535",
            quoted_config_value(var, raw)
        )
    })?;
    if port == 0 {
        return Err(format!(
            "Invalid {var} {}: port must be 1-65535",
            quoted_config_value(var, raw)
        ));
    }
    Ok(port)
}

/// Parse the TPROXY firewall mark, accepting `0x`-prefixed hex or decimal. A
/// zero mark is rejected — the policy routing rule and `--tproxy-mark` selector
/// would match unmarked packets and steer all local traffic into the TPROXY
/// table.
fn parse_tproxy_mark(raw: &str) -> Result<u32, String> {
    let trimmed = raw.trim();
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16)
    } else {
        trimmed.parse::<u32>()
    }
    .map_err(|_| {
        format!(
            "Invalid FERRUM_MESH_TPROXY_MARK {}. Expected a 32-bit hex (0x...) or decimal value",
            quoted_config_value("FERRUM_MESH_TPROXY_MARK", raw)
        )
    })?;
    if parsed == 0 {
        return Err(format!(
            "Invalid FERRUM_MESH_TPROXY_MARK {}: mark must be non-zero",
            quoted_config_value("FERRUM_MESH_TPROXY_MARK", raw)
        ));
    }
    Ok(parsed)
}

pub(crate) fn validate_proxy_uid(uid: u32) -> Result<(), String> {
    if uid == 0 {
        return Err(
            "Invalid FERRUM_MESH_PROXY_UID: proxy UID must be non-zero to avoid bypassing capture for all root processes"
                .to_string(),
        );
    }
    Ok(())
}

pub(crate) fn parse_proxy_uid(raw: &str) -> Result<u32, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(DEFAULT_PROXY_UID);
    }
    let uid = trimmed.parse::<u32>().map_err(|_| {
        format!(
            "Invalid FERRUM_MESH_PROXY_UID {}. Expected unsigned integer",
            quoted_config_value("FERRUM_MESH_PROXY_UID", raw)
        )
    })?;
    validate_proxy_uid(uid)?;
    Ok(uid)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IptablesPlan {
    pub v4_commands: Vec<String>,
    pub v6_commands: Vec<String>,
    pub ip6tables_mode: Ip6TablesMode,
}

impl IptablesPlan {
    /// Reject an invalid proxy UID before rendering either address family's rules.
    pub fn for_config(config: &CaptureConfig) -> Result<Self, String> {
        config.validate_proxy_uid()?;
        // IPv4 always emits chains because inbound capture is protocol-wide for
        // an active address family, even when only IPv6 outbound CIDRs exist.
        let v4_commands = commands_for_family("iptables", config, CidrFamily::V4, true);
        let v6_enabled = config.ip6tables_mode != Ip6TablesMode::Disabled;
        let v6_has_cidrs = config
            .include_cidrs
            .iter()
            .chain(config.exclude_cidrs.iter())
            .any(|cidr| cidr_family(cidr) == Some(CidrFamily::V6));
        let v6_commands = if v6_enabled && v6_has_cidrs {
            commands_for_family("ip6tables", config, CidrFamily::V6, false)
        } else if v6_has_cidrs {
            warn!(
                "Skipping IPv6 mesh capture rules because FERRUM_MESH_IP6TABLES_ENABLED is disabled"
            );
            Vec::new()
        } else {
            Vec::new()
        };

        Ok(Self {
            v4_commands,
            v6_commands,
            ip6tables_mode: config.ip6tables_mode,
        })
    }

    /// Build a plan containing ONLY the UDP TPROXY capture rules — never the TCP
    /// `nat` REDIRECT chains — for the Ambient per-pod-netns UDP producer
    /// (`src/proxy/netns_udp_capture.rs`).
    ///
    /// The Ambient proxy installs these from INSIDE each enrolled pod's netns.
    /// Ambient's TCP capture rides eBPF/HBONE (not iptables), so emitting the TCP
    /// nat chains here would be wrong; the Sidecar injector keeps using
    /// [`Self::for_config`] (TCP REDIRECT + UDP TPROXY together). The UDP rules
    /// themselves are generated by the SAME `udp_tproxy_commands_for_family`
    /// the injector uses, so producer and injector never diverge.
    ///
    /// Family gating mirrors [`Self::for_config`]: IPv4 always, IPv6 only when
    /// `ip6tables` is enabled AND a v6 CIDR is configured. The whole plan is
    /// empty when `udp_capture_enabled` is `false` or `host_netns` is `true`
    /// (the latter via `udp_tproxy_commands_for_family`'s host-netns
    /// suppression, preserving the "no host-netns UDP rules" invariant even
    /// though the producer never runs in host netns).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn udp_only_for_config(config: &CaptureConfig) -> Result<Self, String> {
        config.validate_proxy_uid()?;
        if !config.udp_capture_enabled {
            return Ok(Self {
                v4_commands: Vec::new(),
                v6_commands: Vec::new(),
                ip6tables_mode: config.ip6tables_mode,
            });
        }
        let v4_commands = udp_only_commands_for_family(config, CidrFamily::V4);
        let v6_enabled = config.ip6tables_mode != Ip6TablesMode::Disabled;
        let v6_has_cidrs = config
            .include_cidrs
            .iter()
            .chain(config.exclude_cidrs.iter())
            .any(|cidr| cidr_family(cidr) == Some(CidrFamily::V6));
        let v6_commands = if v6_enabled && v6_has_cidrs {
            udp_only_commands_for_family(config, CidrFamily::V6)
        } else {
            Vec::new()
        };
        Ok(Self {
            v4_commands,
            v6_commands,
            ip6tables_mode: config.ip6tables_mode,
        })
    }

    /// Generate iptables commands that reverse the setup performed by
    /// [`for_config`]. The cleanup order matters:
    ///
    /// 1. Delete the jump rules from the built-in chains (`PREROUTING`,
    ///    `OUTPUT`) so no new traffic enters the custom chains.
    /// 2. Flush the custom chains (remove all rules inside them).
    /// 3. Delete the now-empty custom chains.
    ///
    /// Each command uses `2>/dev/null || true` so partial cleanup (e.g.
    /// chains already removed by a previous run) does not fail the overall
    /// teardown.
    /// TCP-chain teardown plus, when `udp_capture_enabled`, the UDP TPROXY
    /// `mangle` chains and the Ferrum-owned routing rule/route. The UDP teardown
    /// is gated so a non-UDP install never touches routing state it never
    /// created (codex r1); pass the install's `udp_capture_enabled` flag.
    /// Flat IPv4 cleanup (iptables-table teardown then raw routing teardown).
    /// Test-only convenience; production node-agent code uses [`Self::cleanup_split`]
    /// so it can guard only the table portion behind the `ip6tables` probe.
    #[cfg(test)]
    pub fn cleanup_commands(udp_capture_enabled: bool) -> Vec<String> {
        cleanup_commands_for("iptables", udp_capture_enabled).into_flat()
    }

    /// Flat IPv6 cleanup. Test-only; see [`Self::cleanup_v6_split`].
    #[cfg(test)]
    pub fn cleanup_v6_commands(udp_capture_enabled: bool) -> Vec<String> {
        cleanup_commands_for("ip6tables", udp_capture_enabled).into_flat()
    }

    /// The IPv4 cleanup split into the iptables-table teardown vs. the raw `ip`
    /// routing teardown. The node-agent emits the routing teardown UNCONDITIONALLY
    /// (it is `ip`, not `iptables`/`ip6tables`); see [`Self::cleanup_v6_split`].
    pub fn cleanup_split(udp_capture_enabled: bool) -> CleanupCommands {
        cleanup_commands_for("iptables", udp_capture_enabled)
    }

    /// The IPv6 cleanup split into the **ip6tables-table** teardown (`iptables`,
    /// which the node-agent guards behind an `ip6tables` availability probe) and
    /// the **raw `ip -6` routing** teardown (`ip_routing`, the fwmark rule + local
    /// route). The routing teardown MUST be emitted UNCONDITIONALLY — `ip -6` can
    /// remove the rule/route even when `ip6tables` is missing, so wrapping it in
    /// the ip6tables guard would leak the fwmark rule + local route and keep
    /// diverting marked UDP after shutdown (codex r3).
    pub fn cleanup_v6_split(udp_capture_enabled: bool) -> CleanupCommands {
        cleanup_commands_for("ip6tables", udp_capture_enabled)
    }

    /// The EXACT Ferrum-owned **IPv4** UDP TPROXY teardown (mangle chains +
    /// fwmark rule by stable priority + local route), split like
    /// [`Self::cleanup_split`]. Contains ONLY UDP state — never the TCP nat
    /// chains — so the node-agent runs it UNCONDITIONALLY before setup to reap
    /// stale UDP state left by a prior UDP-enabled-then-crashed run, even when the
    /// current `FERRUM_MESH_CAPTURE_UDP_ENABLED` is `false` (codex r4). Idempotent
    /// and best-effort; a no-op when no UDP state exists.
    pub fn udp_teardown_split() -> CleanupCommands {
        udp_teardown_for("iptables")
    }

    /// The EXACT Ferrum-owned **IPv6** UDP TPROXY teardown, split like
    /// [`Self::cleanup_v6_split`] (the `iptables`/ip6tables-table half is guarded
    /// behind the node-agent's `ip6tables` probe; the raw `ip -6` routing half is
    /// emitted unconditionally). See [`Self::udp_teardown_split`].
    pub fn udp_teardown_v6_split() -> CleanupCommands {
        udp_teardown_for("ip6tables")
    }
}

/// A capture-cleanup command list split by whether each command touches an
/// iptables/ip6tables TABLE (`iptables`) or is a raw `ip`/`ip -6` routing command
/// (`ip_routing`). The node-agent guards only the `iptables` portion behind an
/// `ip6tables`-availability probe for IPv6; the `ip_routing` portion is always
/// emitted so routing state is torn down regardless of `ip6tables` availability.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CleanupCommands {
    /// `iptables`/`ip6tables` table teardown (jump deletes, chain flush, chain
    /// delete) — for the IPv6 family these are guarded behind an `ip6tables`
    /// availability probe by the node-agent.
    pub iptables: Vec<String>,
    /// Raw `ip`/`ip -6` routing teardown (fwmark `ip rule` + local `ip route`).
    /// Emitted unconditionally — `ip` does not depend on `ip6tables`.
    pub ip_routing: Vec<String>,
}

impl CleanupCommands {
    /// iptables-table teardown first, then the routing teardown — preserving the
    /// original flat ordering for the init-container cleanup script. Test-only
    /// (production composes the two halves with per-half guarding).
    #[cfg(test)]
    fn into_flat(self) -> Vec<String> {
        let mut commands = self.iptables;
        commands.extend(self.ip_routing);
        commands
    }
}

// EbpfPlan and helpers are consumed by the node-agent eBPF capture path
// (ambient DaemonSet integration). The sidecar injector deliberately does NOT
// inject an init container for eBPF mode — privileged capabilities would cause
// Pod Security Baseline/Restricted admission rejection on every pod, even when
// the script does nothing on 5.7+ kernels.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfPlan {
    pub enabled: bool,
    pub fallback: IptablesPlan,
    pub required_kernel: &'static str,
}

#[allow(dead_code)]
impl EbpfPlan {
    pub fn for_config(config: &CaptureConfig) -> Result<Self, String> {
        Ok(Self {
            enabled: config.mode == CaptureMode::Ebpf,
            fallback: IptablesPlan::for_config(config)?,
            required_kernel: "5.7",
        })
    }

    pub fn fallback_script(&self) -> String {
        let fallback_cmds = self.fallback.script();
        let (major, minor) = parse_kernel_requirement(self.required_kernel);
        format!(
            "MAJOR=$(uname -r | cut -d. -f1)\n\
             MINOR=$(uname -r | cut -d. -f2)\n\
             if [ \"$MAJOR\" -lt {major} ] || \
             {{ [ \"$MAJOR\" -eq {major} ] && [ \"$MINOR\" -lt {minor} ]; }}; then\n\
             echo \"Kernel $(uname -r) < {req}, falling back to iptables\"\n\
             {fallback_cmds}\n\
             else\n\
             echo \"Kernel $(uname -r) supports eBPF capture, skipping iptables\"\n\
             fi",
            req = self.required_kernel,
        )
    }
}

impl IptablesPlan {
    pub fn script(&self) -> String {
        // `set -e` makes the injected init container fail **closed**: if any
        // iptables rule fails to apply, the script exits non-zero and the pod's
        // init phase fails, instead of starting the workload with a partial
        // capture ruleset that would let egress silently bypass the mesh proxy
        // (and therefore `mesh_authz`). The idempotent command shapes are
        // `set -e`-safe: `-N ... || true` and `-C ... || -A ...` tolerate the
        // expected existence probes, while the ordered safety rule uses
        // `-D ... || true; -I ... 1` and therefore still aborts on a real insert
        // failure.
        format!(
            "set -e\n{}",
            iptables_script(
                &self.v4_commands,
                &self.v6_commands,
                self.ip6tables_mode,
                true,
            )
        )
    }

    /// The UDP-only `set -e` setup script the Ambient per-pod-netns producer runs
    /// INSIDE each enrolled pod's netns. Builds [`Self::udp_only_for_config`] and
    /// renders it fail-closed: any rule failure aborts (`set -e`), so the producer
    /// treats a partial install as a failure, tears its partial state back down,
    /// and retries — never leaving a pod half-captured.
    ///
    /// The IPv6 block probes the **`mangle`** table (where the UDP TPROXY chains
    /// live), NOT `nat` — a host with `mangle` but no `nat` table must still run
    /// the UDP v6 rules. Empty (`""`) when UDP capture is off, `host_netns` is
    /// set, or no family emitted rules.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn udp_setup_script(config: &CaptureConfig) -> Result<String, String> {
        let plan = Self::udp_only_for_config(config)?;
        if plan.v4_commands.is_empty() && plan.v6_commands.is_empty() {
            return Ok(String::new());
        }
        Ok(format!(
            "set -e\n{}",
            udp_iptables_script(
                &plan.v4_commands,
                &plan.v6_commands,
                plan.ip6tables_mode,
                true
            )
        ))
    }

    /// Build the fail-closed UDP egress guard installed before the Ambient
    /// per-pod-netns producer touches stale capture state or attempts its socket
    /// bind. The guard mirrors the configured outbound capture scope exactly
    /// (includes, excludes, address family, and non-LOCAL direction) and uses
    /// dedicated alternating chains, so a guarded retry never flushes the
    /// currently active guard before its replacement is live.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn udp_fail_closed_script(config: &CaptureConfig) -> String {
        let v4_commands = udp_fail_closed_commands_for_family("iptables", config, CidrFamily::V4);
        let v6_enabled = config.ip6tables_mode != Ip6TablesMode::Disabled;
        let v6_has_cidrs = config
            .include_cidrs
            .iter()
            .chain(config.exclude_cidrs.iter())
            .any(|cidr| cidr_family(cidr) == Some(CidrFamily::V6));
        let v6_commands = if v6_enabled && v6_has_cidrs {
            udp_fail_closed_commands_for_family("ip6tables", config, CidrFamily::V6)
        } else {
            Vec::new()
        };
        if v4_commands.is_empty() && v6_commands.is_empty() {
            return String::new();
        }
        format!(
            "set -e\n{}",
            udp_iptables_script(&v4_commands, &v6_commands, config.ip6tables_mode, true,)
        )
    }

    /// Remove only the fail-closed guard chains. Called after the capture socket
    /// has been adopted and the complete TPROXY ruleset is installed, so traffic
    /// switches directly from DROP guard to live capture.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn udp_fail_closed_teardown_script() -> String {
        // Unlike removal during final cleanup, this is a readiness transition:
        // returning success while an OUTPUT jump remains would leave an otherwise
        // healthy producer black-holed indefinitely. Delete every duplicate jump
        // under `set -e`; a failed deletion aborts so the caller tears live capture
        // back down and retries with the guard deliberately retained.
        let mut chunks = vec!["set -e".to_string()];
        chunks.extend(udp_fail_closed_release_for("iptables"));
        // Probe stale IPv6 guards regardless of the current install setting. A
        // pod may restart with IPv6 capture disabled after an earlier enabled
        // producer retained a v6 guard. Resource errors (notably xtables-lock
        // timeout) remain fatal; only an unavailable binary/table is skipped.
        let v6_release = udp_fail_closed_release_for("ip6tables").join("\n");
        chunks.push(ip6tables_strict_probe_guard(&v6_release, "mangle"));
        chunks.join("\n")
    }

    /// Strictly detach the normal UDP capture path from locally generated
    /// traffic while a retained fail-closed guard is still active. Abandonment
    /// cleanup runs this before releasing the guard: if a partial live setup left
    /// the OUTPUT-mark jump behind, an xtables error must not expose that
    /// socketless TPROXY path after the DROP guard is removed.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn udp_capture_output_release_script() -> String {
        let mut chunks = vec!["set -e".to_string()];
        chunks.push(udp_strict_output_jump_release_for(
            "iptables",
            "FERRUM_MESH_UDP_OUTPUT_MARK",
        ));
        let v6_release =
            udp_strict_output_jump_release_for("ip6tables", "FERRUM_MESH_UDP_OUTPUT_MARK");
        chunks.push(ip6tables_strict_probe_guard(&v6_release, "mangle"));
        chunks.join("\n")
    }

    /// Remove the normal UDP capture chains/routing while leaving any active
    /// fail-closed guard intact. The producer uses this after installing the
    /// guard and before binding/rebuilding the live capture path.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn udp_capture_rules_teardown_script(include_v6: bool) -> String {
        let v4 = udp_capture_teardown_for("iptables");
        let mut chunks = Vec::new();
        chunks.extend(v4.iptables);
        chunks.extend(v4.ip_routing);
        if include_v6 {
            let v6 = udp_capture_teardown_for("ip6tables");
            chunks.extend(
                v6.iptables
                    .iter()
                    .map(|cmd| ip6tables_probe_guard(cmd, "mangle")),
            );
            chunks.extend(v6.ip_routing);
        }
        chunks.join("\n")
    }

    /// The UDP-only teardown script the Ambient producer runs INSIDE a pod netns
    /// on pod removal, disabled-mode cleanup, or shutdown. Reuses the
    /// EXACT Ferrum-owned UDP teardown ([`Self::udp_teardown_split`] /
    /// [`Self::udp_teardown_v6_split`]) so producer cleanup and injector/node-agent
    /// cleanup never diverge, including the dedicated fail-closed guards. Guard
    /// OUTPUT jumps are removed exhaustively and treat resource errors as fatal,
    /// so cleanup cannot report success with a duplicate DROP jump still active;
    /// the remaining chain/routing teardown is best-effort for partial or
    /// already-absent state. The raw `ip`/`ip -6` routing teardown is emitted unconditionally
    /// (it does not depend on `ip6tables`); only the `ip6tables`-TABLE teardown is
    /// guarded behind an `ip6tables` (`mangle`) availability probe.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn udp_teardown_script(include_v6: bool) -> String {
        let v4 = Self::udp_teardown_split();
        let mut chunks: Vec<String> = Vec::new();
        chunks.extend(v4.iptables);
        chunks.extend(v4.ip_routing);
        if include_v6 {
            let v6 = Self::udp_teardown_v6_split();
            chunks.extend(
                v6.iptables
                    .iter()
                    .map(|cmd| ip6tables_probe_guard(cmd, "mangle")),
            );
            chunks.extend(v6.ip_routing);
        } else {
            // Current IPv6 disablement must not orphan a guard installed by an
            // earlier enabled process. Limit the cross-setting cleanup to the
            // dedicated guard chains; normal v6 capture/routing remains gated by
            // `include_v6` as before.
            chunks.extend(
                udp_fail_closed_teardown_for("ip6tables")
                    .iter()
                    .map(|cmd| ip6tables_probe_guard(cmd, "mangle")),
            );
        }
        chunks.join("\n")
    }

    /// Build the HOST-network UDP capture plan (issue #3288) for the enrolled
    /// pods' host-side interfaces.
    ///
    /// `ifaces` is validated before a single command is rendered: the names are
    /// interpolated into an `iptables -i <iface>` argument inside a `sh -c`
    /// script, and they originate outside this process (kernel/procfs discovery
    /// driven by the node-agent's registry). A rejected name fails the whole plan
    /// rather than being skipped, so a hostile or corrupt entry can never yield a
    /// partially-scoped ruleset that silently captures the wrong pods.
    ///
    /// Family gating mirrors [`Self::udp_only_for_config`]: IPv4 always, IPv6
    /// only when `ip6tables` is enabled AND a v6 CIDR is configured.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn host_udp_for_config(config: &CaptureConfig, ifaces: &[String]) -> Result<Self, String> {
        config.validate_proxy_uid()?;
        if !config.udp_capture_enabled {
            return Err(
                "host-network UDP capture requires FERRUM_MESH_CAPTURE_UDP_ENABLED=true"
                    .to_string(),
            );
        }
        validate_host_capture_interfaces(ifaces)?;
        let v4_commands = host_udp_commands_for_family(config, CidrFamily::V4, ifaces);
        let v6_enabled = config.ip6tables_mode != Ip6TablesMode::Disabled;
        let v6_has_cidrs = config
            .include_cidrs
            .iter()
            .chain(config.exclude_cidrs.iter())
            .any(|cidr| cidr_family(cidr) == Some(CidrFamily::V6));
        let v6_commands = if v6_enabled && v6_has_cidrs {
            host_udp_commands_for_family(config, CidrFamily::V6, ifaces)
        } else {
            Vec::new()
        };
        Ok(Self {
            v4_commands,
            v6_commands,
            ip6tables_mode: config.ip6tables_mode,
        })
    }

    /// The `set -e` host UDP capture setup script. Fail-closed: any rule failure
    /// aborts, so the caller treats a partial install as a failure, tears its
    /// partial state down, and retries with the DROP guard still active.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn host_udp_setup_script(
        config: &CaptureConfig,
        ifaces: &[String],
    ) -> Result<String, String> {
        let plan = Self::host_udp_for_config(config, ifaces)?;
        if plan.v4_commands.is_empty() && plan.v6_commands.is_empty() {
            return Err(
                "host-network UDP capture emitted no rules for any address family; check \
                 FERRUM_MESH_CAPTURE_INCLUDE_CIDRS / includeOutboundPorts"
                    .to_string(),
            );
        }
        Ok(format!(
            "set -e\n{}",
            udp_iptables_script(
                &plan.v4_commands,
                &plan.v6_commands,
                plan.ip6tables_mode,
                true
            )
        ))
    }

    /// The `set -e` fail-closed DROP guard installed BEFORE the host capture
    /// path is (re)built or the transparent socket is bound. It mirrors the
    /// configured capture scope exactly and uses alternating chains, so a
    /// reconcile never flushes the currently active guard before its replacement
    /// is live. Returns an empty string when there is nothing to guard (no
    /// enrolled interfaces yet).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn host_udp_guard_script(
        config: &CaptureConfig,
        ifaces: &[String],
    ) -> Result<String, String> {
        validate_host_capture_interfaces(ifaces)?;
        let v4_commands =
            host_udp_guard_commands_for_family("iptables", config, CidrFamily::V4, ifaces);
        let v6_enabled = config.ip6tables_mode != Ip6TablesMode::Disabled;
        let v6_has_cidrs = config
            .include_cidrs
            .iter()
            .chain(config.exclude_cidrs.iter())
            .any(|cidr| cidr_family(cidr) == Some(CidrFamily::V6));
        let v6_commands = if v6_enabled && v6_has_cidrs {
            host_udp_guard_commands_for_family("ip6tables", config, CidrFamily::V6, ifaces)
        } else {
            Vec::new()
        };
        if v4_commands.is_empty() && v6_commands.is_empty() {
            return Ok(String::new());
        }
        Ok(format!(
            "set -e\n{}",
            udp_iptables_script(&v4_commands, &v6_commands, config.ip6tables_mode, true)
        ))
    }

    /// Strictly remove the host fail-closed guard chains after the capture path
    /// is live. Deletion failures abort (`set -e`) so the caller can never report
    /// readiness while a DROP jump is still black-holing enrolled egress.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn host_udp_guard_release_script() -> String {
        let mut chunks = vec!["set -e".to_string()];
        chunks.extend(host_udp_guard_teardown_for("iptables"));
        // Probe stale IPv6 guards regardless of the current setting: a node can
        // restart with IPv6 capture disabled after an earlier enabled generation
        // retained a v6 guard. Only an unavailable binary/table is skipped;
        // resource errors (notably an xtables-lock timeout) stay fatal.
        let v6_release = host_udp_guard_teardown_for("ip6tables").join("\n");
        chunks.push(ip6tables_strict_probe_guard(&v6_release, "mangle"));
        chunks.join("\n")
    }

    /// Remove the host capture chain + routing while leaving any active
    /// fail-closed guard intact. Used before rebuilding and on setup failure, so
    /// a retry never reopens plaintext egress.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn host_udp_capture_rules_teardown_script() -> String {
        let v4 = host_udp_capture_teardown_for("iptables");
        let mut chunks = Vec::new();
        chunks.extend(v4.iptables);
        chunks.extend(v4.ip_routing);
        // Always probe for stale IPv6 state, even when IPv6 capture is disabled
        // in the current generation. A prior enabled generation may have left a
        // jump, chain, fwmark rule, or local route behind.
        let v6 = host_udp_capture_teardown_for("ip6tables");
        chunks.extend(
            v6.iptables
                .iter()
                .map(|cmd| ip6tables_probe_guard(cmd, "mangle")),
        );
        chunks.extend(v6.ip_routing);
        chunks.join("\n")
    }

    /// Complete host UDP teardown (capture path + both guard generations),
    /// used on shutdown, on disabling the path, and unconditionally before setup
    /// so a prior crashed generation's state is reaped even when the current
    /// configuration would emit nothing.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn host_udp_teardown_script() -> String {
        let v4 = host_udp_teardown_for("iptables");
        let mut chunks: Vec<String> = Vec::new();
        chunks.extend(v4.iptables);
        chunks.extend(v4.ip_routing);
        // Complete teardown is generation-independent: always probe IPv6 table
        // state and always remove the raw IPv6 routing objects. This matters when
        // a node restarts with IPv6 capture disabled after an enabled generation.
        let v6 = host_udp_teardown_for("ip6tables");
        chunks.extend(
            v6.iptables
                .iter()
                .map(|cmd| ip6tables_probe_guard(cmd, "mangle")),
        );
        chunks.extend(v6.ip_routing);
        chunks.join("\n")
    }

    #[cfg(test)]
    pub fn cleanup_script(
        include_v6: bool,
        ip6tables_mode: Ip6TablesMode,
        udp_capture_enabled: bool,
    ) -> String {
        let v4_commands = Self::cleanup_commands(udp_capture_enabled);
        let v6_commands = if include_v6 {
            Self::cleanup_v6_commands(udp_capture_enabled)
        } else {
            Vec::new()
        };
        iptables_script(&v4_commands, &v6_commands, ip6tables_mode, false)
    }
}

#[allow(dead_code)]
fn parse_kernel_requirement(version: &str) -> (u32, u32) {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|p| p.parse().ok()).unwrap_or(5);
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(7);
    (major, minor)
}

pub fn should_fallback_to_iptables(kernel_release: &str) -> bool {
    let mut parts = kernel_release.split('.');
    let major = parts.next().and_then(|p| p.parse::<u32>().ok());
    let minor = parts.next().and_then(|p| p.parse::<u32>().ok());
    match (major, minor) {
        (Some(major), Some(minor)) => major < 5 || (major == 5 && minor < 7),
        _ => true,
    }
}

pub fn validate_cidr_list(cidrs: &[String]) -> Result<(), String> {
    for cidr in cidrs {
        let Some((addr, prefix)) = cidr.split_once('/') else {
            return Err(format!("CIDR {cidr:?} must include a prefix length"));
        };
        let ip: IpAddr = addr
            .parse()
            .map_err(|_| format!("CIDR {cidr:?} has invalid IP address"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| format!("CIDR {cidr:?} has invalid prefix length"))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!(
                "CIDR {cidr:?} prefix length \"{prefix}\" exceeds max {max}"
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CidrFamily {
    V4,
    V6,
}

fn cidr_family(cidr: &str) -> Option<CidrFamily> {
    cidr.split_once('/')
        .and_then(|(addr, _)| addr.parse::<IpAddr>().ok())
        .map(|ip| {
            if ip.is_ipv4() {
                CidrFamily::V4
            } else {
                CidrFamily::V6
            }
        })
}

fn commands_for_family(
    binary: &str,
    config: &CaptureConfig,
    family: CidrFamily,
    emit_inbound_regardless: bool,
) -> Vec<String> {
    let include_cidrs: Vec<&str> = config
        .include_cidrs
        .iter()
        .filter(|cidr| cidr_family(cidr) == Some(family))
        .map(String::as_str)
        .collect();
    let exclude_cidrs: Vec<&str> = config
        .exclude_cidrs
        .iter()
        .filter(|cidr| cidr_family(cidr) == Some(family))
        .map(String::as_str)
        .collect();
    // Inbound capture is protocol-wide for an active address family; IPv4
    // therefore keeps inbound chains even when only IPv6 outbound CIDRs exist.
    if !emit_inbound_regardless && include_cidrs.is_empty() && exclude_cidrs.is_empty() {
        return Vec::new();
    }

    let mut commands = Vec::new();
    commands.push(idempotent_new_chain(binary, "nat", "FERRUM_MESH_INBOUND"));
    commands.push(idempotent_new_chain(binary, "nat", "FERRUM_MESH_OUTBOUND"));

    // Loopback / pod-self RETURN, emitted FIRST so it precedes every REDIRECT in
    // this chain (issue #4276). `nat OUTPUT` is traversed by locally generated
    // packets, including the universal multi-container-pod pattern where the app
    // dials a sidecar over `127.0.0.1` (`postgres`, `redis`, an app-local admin
    // port). With the shipped defaults the include rule is a catch-all
    // `-p tcp -d 0.0.0.0/0 -j REDIRECT --to-ports <outbound>`, so without this
    // RETURN that intra-pod connection is DNAT'd into the mesh outbound proxy,
    // recovers `SO_ORIGINAL_DST = 127.0.0.1:<app port>`, matches no mesh route,
    // and is handed to the HTTP path (or denied outright under
    // `outboundTrafficPolicy: REGISTRY_ONLY`). Istio's `ISTIO_OUTPUT` carries
    // `-d 127.0.0.1/32 -j RETURN` for exactly this.
    //
    // `-m addrtype --dst-type LOCAL` is the SAME discriminator the UDP sibling
    // chain already uses (`udp_tproxy_commands_for_family`'s complementary
    // `! --dst-type LOCAL` egress scope), and in the POD netns it covers both
    // loopback and the pod's own IP in one family-agnostic rule — so the
    // `ip6tables` fan-out gets the identical protection without a second literal.
    //
    // Gated on `host_netns` for the same reason the UDP path is: in the HOST
    // namespace pod IPs are FORWARDED rather than `LOCAL`, so the discriminator
    // does not describe "this workload's own address" there. The TCP chains are
    // only ever rendered by the injector's pod-netns init container today, and
    // this keeps that invariant explicit rather than assumed.
    if !config.host_netns {
        commands.push(idempotent_insert_first(
            binary,
            "nat",
            "FERRUM_MESH_OUTBOUND",
            "-m addrtype --dst-type LOCAL -j RETURN",
        ));
    }

    for cidr in &exclude_cidrs {
        commands.push(idempotent_append(
            binary,
            "nat",
            "FERRUM_MESH_OUTBOUND",
            &format!("-d {cidr} -j RETURN"),
        ));
    }
    for port in &config.exclude_ports {
        commands.push(idempotent_append(
            binary,
            "nat",
            "FERRUM_MESH_OUTBOUND",
            &format!("-p tcp --dport {port} -j RETURN"),
        ));
    }
    if let Some(uid) = config.proxy_uid {
        commands.push(idempotent_append(
            binary,
            "nat",
            "FERRUM_MESH_OUTBOUND",
            &format!("-m owner --uid-owner {uid} -j RETURN"),
        ));
    }
    if config.include_all_outbound_ports {
        commands.push(idempotent_append(
            binary,
            "nat",
            "FERRUM_MESH_OUTBOUND",
            &format!("-p tcp -j REDIRECT --to-ports {}", config.outbound_port),
        ));
    } else {
        // includeOutboundPorts without an explicit include-CIDR annotation means
        // "capture only these ports" rather than "add these ports to the
        // implicit 0.0.0.0/0 catch-all". Explicit include CIDRs stay additive.
        let emit_include_cidrs =
            config.include_outbound_ports.is_empty() || config.include_cidrs_explicit;
        if emit_include_cidrs {
            if include_cidrs.is_empty() {
                let has_include_cidrs_for_other_family = config
                    .include_cidrs
                    .iter()
                    .any(|cidr| cidr_family(cidr).is_some_and(|cidr_family| cidr_family != family));
                if config.include_cidrs_explicit || !has_include_cidrs_for_other_family {
                    commands.push(idempotent_append(
                        binary,
                        "nat",
                        "FERRUM_MESH_OUTBOUND",
                        &format!("-p tcp -j REDIRECT --to-ports {}", config.outbound_port),
                    ));
                }
            } else {
                for cidr in &include_cidrs {
                    commands.push(idempotent_append(
                        binary,
                        "nat",
                        "FERRUM_MESH_OUTBOUND",
                        &format!(
                            "-p tcp -d {cidr} -j REDIRECT --to-ports {}",
                            config.outbound_port
                        ),
                    ));
                }
            }
        }
        for port in &config.include_outbound_ports {
            commands.push(idempotent_append(
                binary,
                "nat",
                "FERRUM_MESH_OUTBOUND",
                &format!(
                    "-p tcp --dport {port} -j REDIRECT --to-ports {}",
                    config.outbound_port
                ),
            ));
        }
    }
    // Inbound port exclusions MUST be appended before the catch-all REDIRECT
    // below — once REDIRECT fires the chain returns, so any RETURN rule placed
    // after it would be silently bypassed.
    for port in &config.exclude_inbound_ports {
        commands.push(idempotent_append(
            binary,
            "nat",
            "FERRUM_MESH_INBOUND",
            &format!("-p tcp --dport {port} -j RETURN"),
        ));
    }
    for port in &config.exclude_inbound_tcp_ports {
        commands.push(idempotent_append(
            binary,
            "nat",
            "FERRUM_MESH_INBOUND",
            &format!("-p tcp --dport {port} -j RETURN"),
        ));
    }
    // CIDR include/exclude settings scope outbound capture only. Once this
    // address family is active, inbound capture stays protocol-wide so replies
    // and server-initiated inbound connections are consistently redirected.
    commands.push(idempotent_append(
        binary,
        "nat",
        "FERRUM_MESH_INBOUND",
        &format!("-p tcp -j REDIRECT --to-ports {}", config.inbound_port),
    ));
    commands.push(idempotent_append(
        binary,
        "nat",
        "PREROUTING",
        "-p tcp -j FERRUM_MESH_INBOUND",
    ));
    commands.push(idempotent_append(
        binary,
        "nat",
        "OUTPUT",
        "-p tcp -j FERRUM_MESH_OUTBOUND",
    ));
    if config.udp_capture_enabled {
        commands.extend(udp_tproxy_commands_for_family(
            binary,
            config,
            family,
            &include_cidrs,
            &exclude_cidrs,
            // Injector (Sidecar): capture inbound-to-pod UDP too (fail-closed).
            true,
        ));
    }
    commands
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn udp_outbound_selectors_for_family(
    config: &CaptureConfig,
    family: CidrFamily,
    include_cidrs: &[&str],
) -> Vec<String> {
    // When an explicit include list selects only the other address family, do
    // not synthesize this family's catch-all. Port includes are family-agnostic
    // and still apply. This is the shared source of truth for both live TPROXY
    // capture and the fail-closed guard; security fallback must never broaden
    // or narrow the operator's configured capture scope.
    let suppress_catch_all = config.include_cidrs_explicit
        && include_cidrs.is_empty()
        && config
            .include_cidrs
            .iter()
            .any(|cidr| cidr_family(cidr).is_some_and(|cidr_family| cidr_family != family));

    let mut selectors = Vec::new();
    if config.include_all_outbound_ports {
        if !suppress_catch_all {
            selectors.push("-p udp".to_string());
        }
    } else {
        let emit_include_cidrs =
            config.include_outbound_ports.is_empty() || config.include_cidrs_explicit;
        if emit_include_cidrs {
            if include_cidrs.is_empty() {
                if !suppress_catch_all {
                    selectors.push("-p udp".to_string());
                }
            } else {
                selectors.extend(include_cidrs.iter().map(|cidr| format!("-p udp -d {cidr}")));
            }
        }
        selectors.extend(
            config
                .include_outbound_ports
                .iter()
                .map(|port| format!("-p udp --dport {port}")),
        );
    }
    selectors
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn udp_fail_closed_chain_commands(
    binary: &str,
    chain: &str,
    config: &CaptureConfig,
    family: CidrFamily,
    include_cidrs: &[&str],
    exclude_cidrs: &[&str],
) -> Vec<String> {
    let selectors = udp_outbound_selectors_for_family(config, family, include_cidrs);
    if selectors.is_empty() {
        return Vec::new();
    }
    // This builder is used only after the other generation is known to be
    // active (or during the first install). Reset and populate the inactive
    // chain strictly: treating an xtables resource error as "already exists"
    // could leave stale selectors in the replacement guard.
    let mut commands = vec![format!(
        "{binary} -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -N {chain} 2>/dev/null || \
         {binary} -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -F {chain}"
    )];
    for cidr in exclude_cidrs {
        commands.push(format!(
            "{binary} -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -A {chain} \
             -p udp -d {cidr} -j RETURN"
        ));
    }
    for port in &config.exclude_ports {
        commands.push(format!(
            "{binary} -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -A {chain} \
             -p udp --dport {port} -j RETURN"
        ));
    }
    for selector in selectors {
        commands.push(format!(
            "{binary} -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -A {chain} \
             {selector} -m addrtype ! --dst-type LOCAL -j DROP"
        ));
    }
    commands
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn udp_fail_closed_commands_for_family(
    binary: &str,
    config: &CaptureConfig,
    family: CidrFamily,
) -> Vec<String> {
    if !config.udp_capture_enabled || config.host_netns {
        return Vec::new();
    }
    let include_cidrs: Vec<&str> = config
        .include_cidrs
        .iter()
        .filter(|cidr| cidr_family(cidr) == Some(family))
        .map(String::as_str)
        .collect();
    let exclude_cidrs: Vec<&str> = config
        .exclude_cidrs
        .iter()
        .filter(|cidr| cidr_family(cidr) == Some(family))
        .map(String::as_str)
        .collect();
    let build_a = udp_fail_closed_chain_commands(
        binary,
        UDP_FAIL_CLOSED_CHAIN_A,
        config,
        family,
        &include_cidrs,
        &exclude_cidrs,
    );
    if build_a.is_empty() {
        return Vec::new();
    }
    let build_b = udp_fail_closed_chain_commands(
        binary,
        UDP_FAIL_CLOSED_CHAIN_B,
        config,
        family,
        &include_cidrs,
        &exclude_cidrs,
    );
    udp_guard_switch_commands(
        binary,
        "OUTPUT",
        UDP_FAIL_CLOSED_CHAIN_A,
        UDP_FAIL_CLOSED_CHAIN_B,
        &build_a,
        &build_b,
    )
}

/// Render the A/B fail-closed guard switch for one `mangle` hook.
///
/// Shared by the pod-netns producer (hook `OUTPUT`) and the host-netns capture
/// path (hook `PREROUTING`) so the two can never drift in the one place where a
/// mistake is a fail-OPEN window: the replacement guard is fully populated and
/// jumped BEFORE the previous generation's jump is released, so at no point is
/// selected UDP egress unguarded.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn udp_guard_switch_commands(
    binary: &str,
    hook: &str,
    chain_a: &str,
    chain_b: &str,
    build_a: &[String],
    build_b: &[String],
) -> Vec<String> {
    let jump_a = format!("-p udp -j {chain_a}");
    let jump_b = format!("-p udp -j {chain_b}");
    let a_active =
        format!("{binary} -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -C {hook} {jump_a} 2>/dev/null");
    let release_a = udp_strict_jump_release_for(binary, hook, chain_a);
    let release_b = udp_strict_jump_release_for(binary, hook, chain_b);
    let replace_a = [
        release_b.clone(),
        build_b.join("\n"),
        format!("{binary} -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -I {hook} 1 {jump_b}"),
        release_a,
    ]
    .join("\n");
    let replace_b_or_install = [
        build_a.join("\n"),
        format!("{binary} -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -I {hook} 1 {jump_a}"),
        release_b,
    ]
    .join("\n");

    // First-install portability (issue #2084). The active-guard probe below is a
    // `-C OUTPUT ... -j FERRUM_UDP_FAIL_CLOSED_A` rule check. On a fresh pod netns
    // chain A does not exist yet, and the exit status for "jump references a
    // missing user chain" is NOT portable: legacy iptables returns 1 (which we
    // read as "A not active"), but nft-backed iptables (Ubuntu 24.04 runners)
    // returns 2, which the strict `status -ne 1` handler treats as a genuine
    // xtables resource error and aborts the install — the producer then retries
    // forever without ever binding the transparent socket.
    //
    // To make first-install detection portable WITHOUT weakening fail-closed
    // handling of real resource errors, establish chain A's existence separately
    // (via `-S`, a chain listing that does not depend on the missing-target
    // status quirk) BEFORE interpreting the jump probe:
    //   * chain A absent  -> first install (or A fully removed): take the
    //     install/replace-B path directly, never touching the jump probe.
    //   * chain A present -> the jump probe is meaningful: an active jump swaps to
    //     B, an absent jump (status 1) reinstalls A, and any other status is a
    //     genuine xtables error that still aborts the install fail-closed.
    // The existence check itself fails closed too: `-S` returns 1 only for an
    // absent chain; any other non-zero status (e.g. an xtables-lock timeout)
    // aborts rather than being misread as absence.
    let a_exists =
        format!("{binary} -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -S {chain_a} >/dev/null 2>&1");

    vec![format!(
        "if {a_exists}; then\n\
         if {a_active}; then\n{replace_a}\nelse\nstatus=$?\nif [ \"$status\" -ne 1 ]; then\n  echo \"{binary} could not inspect active UDP fail-closed guard (status $status)\" >&2\n  exit \"$status\"\nfi\n{replace_b_or_install}\nfi\n\
         else\nstatus=$?\nif [ \"$status\" -ne 1 ]; then\n  echo \"{binary} could not inspect UDP fail-closed guard chain {chain_a} (status $status)\" >&2\n  exit \"$status\"\nfi\n{replace_b_or_install}\nfi"
    )]
}

/// Emit UDP TPROXY capture rules for one address family (F3 §3.3 Stage 2).
///
/// Unlike the TCP path (`nat`-table REDIRECT, which rewrites the destination to
/// the proxy port), UDP capture uses TPROXY in the `mangle` table: TPROXY
/// delivers the datagram to a transparent socket WITHOUT rewriting its
/// destination, so the Stage 3 listener recovers the original destination
/// per-datagram from the `IP_RECVORIGDSTADDR` cmsg. Transparent delivery
/// additionally needs a firewall mark plus an `ip rule`/`ip route local` so the
/// kernel routes the marked datagram to the local socket.
///
/// The include/exclude/CIDR/uid logic mirrors the TCP outbound chain so
/// operator capture scoping (`includeOutboundPorts`, `excludeOutboundPorts`,
/// include/exclude CIDRs, the proxy-UID self-exclusion) applies identically to
/// UDP.
///
/// **Direction scoping mirrors the TCP chains (codex r2).** The TCP path keeps
/// the two directions disjoint by HOOK — inbound rides `nat PREROUTING`, outbound
/// rides `nat OUTPUT` — so neither swallows the other. TPROXY cannot use that
/// trick (it is `PREROUTING`-only; see below), so BOTH UDP chains are jumped from
/// `mangle PREROUTING`. To keep them from clobbering each other we instead
/// discriminate by DESTINATION ADDRESS TYPE, the pod-IP-agnostic equivalent:
/// - the OUTBOUND chain's TPROXY rules carry `-m addrtype ! --dst-type LOCAL`
///   (egress = a remote/non-local destination), and
/// - the INBOUND catch-all TPROXY carries `-m addrtype --dst-type LOCAL`
///   (inbound = a destination configured on this box, i.e. the pod's own IP).
///
/// The OUTBOUND jump is also installed BEFORE the INBOUND jump so egress is
/// matched/routed first. Without this, the inbound catch-all (xt_TPROXY returns
/// `NF_ACCEPT`, ending PREROUTING traversal) would grab pod EGRESS too — the
/// outbound include/exclude/CIDR/port rules would be silently bypassed.
///
/// **TPROXY is PREROUTING-only; locally-generated egress rides an OUTPUT MARK →
/// lo-reroute → PREROUTING-TPROXY loop (codex r6).** The TPROXY target runs ONLY
/// in `PREROUTING`, never for locally-generated (OUTPUT) packets — jumping into a
/// `-j TPROXY` chain from `mangle OUTPUT` is invalid and can make iptables setup
/// fail. But Linux routes a pod's OWN application UDP egress through
/// OUTPUT→POSTROUTING and NEVER through PREROUTING, so the PREROUTING TPROXY
/// chains alone would never see the primary egress case (outbound UDP capture
/// would be inert in the pod netns). The standard "TPROXY for locally-generated
/// traffic" pattern closes this: a `mangle OUTPUT` chain (`FERRUM_MESH_UDP_OUTPUT_
/// MARK`) MARKs the egress (NOT TPROXY) with the same fwmark the PREROUTING rules
/// use; the existing fwmark `ip rule` (priority [`TPROXY_ROUTE_RULE_PRIORITY`] →
/// table [`TPROXY_ROUTE_TABLE`]) + `ip route add local ... dev lo` reroute the
/// marked datagram to loopback; it re-enters the INPUT path, traverses PREROUTING
/// once, and a mark-match `-j TPROXY` rule (in `FERRUM_MESH_UDP_REINJECT`, jumped
/// from PREROUTING FIRST) captures it to the UDP port. The `local`-route delivery
/// diverts the looped datagram to the INPUT side, so OUTPUT is hit exactly once
/// (no loop), and the OUTPUT chain leads with a `-m mark --mark <mark> -j RETURN`
/// anti-loop guard plus a proxy-UID `-m owner --uid-owner <uid> -j RETURN`
/// self-exclusion (owner-match IS valid in OUTPUT — it is invalid in PREROUTING,
/// which is why the dst-based OUTBOUND chain carries no owner RETURN). The full
/// datapath correctness of this loop is validated by the Stage-7
/// `netns-capture-live` e2e (see `docs/mesh.md`).
///
/// **Fail closed when policy routing is unavailable (codex r2).** TPROXY local
/// delivery REQUIRES the `ip rule` + `ip route local` plumbing; installing the
/// mangle TPROXY rules without it is a silent black-hole (the pod comes up
/// "ready" but captured UDP is never delivered). So when UDP capture is enabled
/// this emits a FATAL `command -v ip` preflight BEFORE any UDP rule (no `ip` ⇒
/// the `set -e` script exits non-zero, installing neither the TPROXY rules nor
/// the routing), and the load-bearing routing ADD commands are NOT `|| true`
/// (a failed add aborts the script). Only the delete-before-add (idempotence)
/// keeps `|| true`. TPROXY rules and routing are installed TOGETHER or not at
/// all — never the half-state of TPROXY-without-routing.
///
/// **Routing is installed BEFORE the PREROUTING jumps (codex r5).** The two
/// `mangle PREROUTING` jumps are what actually start steering UDP into the
/// (initially empty of route) chains; the fwmark `ip rule` + local `ip route`
/// are what make the marked datagrams deliverable. The injector init container
/// runs the whole `set -e` script with NO cleanup trap, so if `ip rule`/`ip
/// route` failed AFTER the jumps were appended the pod would come up with TPROXY
/// chains live but no policy routing — exactly the black-hole this stage avoids.
/// Emitting the routing FIRST means a routing failure aborts the `set -e` script
/// BEFORE any capture is wired (and benefits the node-agent's sequential runner
/// identically). The chains/rules themselves are inert until the jumps are
/// appended last.
///
/// **Host-netns direction split (codex r5).** The inbound vs outbound split
/// below uses `-m addrtype --dst-type LOCAL` / `! --dst-type LOCAL`. That is
/// correct ONLY in the POD netns (the injector), where the pod's own IP is
/// `LOCAL`. The node-agent runs `hostNetwork: true` (host netns) where pod IPs
/// are FORWARDED, not `LOCAL`, so inbound UDP to a pod would match the OUTBOUND
/// `! --dst-type LOCAL` discriminator and be TPROXY'd by the outbound chain
/// (bypassing inbound exclusions). There is no host-netns-safe `addrtype`-style
/// discriminator here without per-pod IP knowledge the iptables fallback does not
/// carry, and this path is inert (flag-gated default-off, no Stage-3 listener,
/// eBPF is the node-agent's primary/supported UDP capture path), so the
/// host-netns case emits NO UDP TPROXY rules rather than silently
/// mis-capturing inbound as outbound. See [`CaptureConfig::host_netns`].
fn udp_tproxy_commands_for_family(
    binary: &str,
    config: &CaptureConfig,
    family: CidrFamily,
    include_cidrs: &[&str],
    exclude_cidrs: &[&str],
    emit_inbound: bool,
) -> Vec<String> {
    // Host-netns UDP suppression (codex r5, finding #1). The `addrtype --dst-type
    // LOCAL` direction split below is only valid in the pod netns; in the host
    // netns it mis-captures inbound-to-pod UDP as outbound. Rather than wire a
    // wrong direction split, the host-netns iptables fallback emits no UDP TPROXY
    // rules at all — eBPF is the node-agent's supported UDP capture path. The
    // node-agent logs the limitation once when it would otherwise emit these.
    if config.host_netns {
        return Vec::new();
    }

    let mark = config.tproxy_mark;
    let mark_arg = format!("0x{mark:x}/0x{TPROXY_MARK_MASK:x}");
    let tproxy_jump = format!(
        "-j TPROXY --on-port {} --tproxy-mark {mark_arg}",
        config.udp_outbound_port
    );
    // OUTPUT-path MARK jump (codex r6): stamps the same fwmark the PREROUTING
    // TPROXY rules use, so a locally-generated pod UDP datagram is rerouted to
    // loopback by the fwmark `ip rule` and re-enters PREROUTING to be TPROXY'd.
    let mark_jump = format!("-j MARK --set-mark {mark_arg}");
    // Outbound (egress) discriminator: a remote/non-local destination. Mirrors
    // the TCP path's hook-based direction separation (which TPROXY can't use,
    // being PREROUTING-only) via destination address type, so this OUTBOUND chain
    // never grabs traffic destined for the pod's own IP (that is the INBOUND
    // chain's job, scoped with the complementary `--dst-type LOCAL`).
    let outbound_dst_scope = "-m addrtype ! --dst-type LOCAL";

    // Compute the OUTBOUND selector specs ONCE (the `-p udp [-d <cidr>|--dport
    // <port>]` portion before any direction-scope / jump), then render two rule
    // sets from them so the PREROUTING TPROXY chain and the OUTPUT MARK chain
    // share identical capture scoping (codex r6):
    //   - PREROUTING TPROXY rules append the `! --dst-type LOCAL` egress scope so
    //     they never grab inbound (the INBOUND chain's `--dst-type LOCAL` job).
    //   - OUTPUT MARK rules ALSO append the SAME `! --dst-type LOCAL` egress scope
    //     (codex r9): in the OUTPUT context the pod's OWN IP and loopback are
    //     `--dst-type LOCAL` (locally generated AND locally destined), while real
    //     egress to other hosts is non-LOCAL. Without this scope the catch-all
    //     `-p udp -d 0.0.0.0/0 -j MARK` would also fwmark pod-to-self / loopback
    //     UDP, reroute it to `lo`, and TPROXY-capture it — but self/loopback UDP
    //     must NOT be captured (only genuine outbound egress). The proxy's own
    //     egress is still separately excluded by the owner-match RETURN at the top
    //     of the OUTPUT chain (owner-match is OUTPUT-context-only — invalid in
    //     PREROUTING); the dst-type scope handles non-proxy local destinations the
    //     owner RETURN cannot (a different UID's pod-to-self/loopback datagram).
    // Shared with the pre-bind fail-closed guard so fallback behavior preserves
    // the exact same include/CIDR/family scope as live capture.
    let outbound_selectors = udp_outbound_selectors_for_family(config, family, include_cidrs);
    let outbound_tproxy_rules: Vec<String> = outbound_selectors
        .iter()
        .map(|sel| format!("{sel} {outbound_dst_scope} {tproxy_jump}"))
        .collect();
    let outbound_mark_rules: Vec<String> = outbound_selectors
        .iter()
        .map(|sel| format!("{sel} {outbound_dst_scope} {mark_jump}"))
        .collect();

    // Whether to emit the INBOUND `--dst-type LOCAL` TPROXY chain/jump, decided by
    // the CALLER (the `emit_inbound` parameter):
    //
    // * The **injector** (Sidecar, `commands_for_family`) passes `true`: inbound
    //   UDP to the pod is captured so unauthenticated pod-destined UDP can't bypass
    //   mesh identity/authz, fail-closing in the egress-only listener.
    //
    // * The **Ambient per-pod-netns producer** (`udp_only_commands_for_family`)
    //   passes `false` — OUTBOUND-ONLY. The producer installs rules INSIDE every
    //   enrolled pod netns, including DESTINATION pods, where an inbound
    //   `--dst-type LOCAL` chain would capture the HBONE datagram relay's own
    //   delivery to the local app (`handle_hbone_udp_request` → local `UdpSocket`
    //   send to the pod app) AND the source pod's return-path reply to the client,
    //   TPROXY them into the egress-only listener, and DROP them — black-holing the
    //   relayed UDP both ways. The producer only needs to capture the pod's
    //   OUTBOUND egress (to relay it); inbound-to-pod UDP must flow to the app
    //   untouched (codex).

    // If this family emits NO TPROXY rule at all (e.g. a pure-CIDR cross-family
    // skip with no port includes), produce NO UDP state for it — no chains, no
    // PREROUTING jumps, no routing — preserving the original cross-family behavior
    // (codex r4) while letting port includes survive (codex r5).
    if outbound_tproxy_rules.is_empty() && !emit_inbound {
        return Vec::new();
    }

    // The fixed prefix (in order):
    //   1. FAIL CLOSED if `ip` is missing — TPROXY local delivery is useless
    //      without the `ip rule`/`ip route local` plumbing, so a runtime image
    //      without `iproute2` must NOT come up with TPROXY-without-routing (a
    //      silent UDP black-hole). Emitted FIRST, before any UDP mangle/TPROXY
    //      rule, so the `set -e` script exits non-zero and installs NOTHING when
    //      `ip` is absent — TPROXY rules and routing go in together or not at all
    //      (codex r2).
    //   2/3. (idempotently) create both mangle chains.
    //   4/5. FLUSH the UDP chains after creating them, BEFORE adding any rule
    //      (codex r3). The per-rule `-C ... || -A` guard is an EXACT match, so on
    //      a reconfiguration that changes `FERRUM_MESH_CAPTURE_UDP_PORT` /
    //      `FERRUM_MESH_TPROXY_MARK` the new TPROXY rule never matches the old
    //      one's `-C` check and is APPENDED AFTER it; iptables preserves rule
    //      order, so the stale rule (old port/mark) stays ahead and black-holes
    //      UDP. Flushing first clears any prior rules so the chain is rebuilt with
    //      only the current config. Flush is idempotent (`-F ... || true`) and
    //      harmless on a fresh chain, keeping the create+flush+populate sequence
    //      rerun-safe.
    let mut commands = vec![
        "command -v ip >/dev/null 2>&1 || { echo \"iproute2 (ip) is required for UDP TPROXY transparent routing\" >&2; exit 1; }"
            .to_string(),
        idempotent_new_chain(binary, "mangle", "FERRUM_MESH_UDP_OUTBOUND"),
        // OUTPUT MARK chain (codex r6): captures the pod's OWN locally-generated
        // UDP egress, which never traverses PREROUTING (Linux routes locally-
        // generated traffic OUTPUT -> POSTROUTING). It MARKs (does not TPROXY —
        // TPROXY is PREROUTING-only) so the fwmark `ip rule` reroutes the datagram
        // to loopback, where it re-enters PREROUTING and the reinject chain (below)
        // captures it.
        idempotent_new_chain(binary, "mangle", "FERRUM_MESH_UDP_OUTPUT_MARK"),
        // REINJECT chain (codex r6): holds the single mark-match `-j TPROXY` rule
        // that captures the OUTPUT-marked datagram after the fwmark route loops it
        // back to loopback and it re-enters PREROUTING. It lives in its OWN custom
        // chain (jumped from PREROUTING first) rather than as a bare PREROUTING
        // rule so the stale-rule-on-mark-change hazard the create+flush sequence
        // already fixes for the other chains (codex r3) covers it too: the built-in
        // PREROUTING chain cannot be flushed, but a custom chain can, and teardown
        // reaps it by name (mark-independent), exactly like the OUTBOUND/INBOUND
        // chains and the priority-keyed fwmark `ip rule`.
        idempotent_new_chain(binary, "mangle", "FERRUM_MESH_UDP_REINJECT"),
        flush_chain(binary, "mangle", "FERRUM_MESH_UDP_OUTBOUND"),
        flush_chain(binary, "mangle", "FERRUM_MESH_UDP_OUTPUT_MARK"),
        flush_chain(binary, "mangle", "FERRUM_MESH_UDP_REINJECT"),
    ];

    // Outbound exclusions first (RETURN wins by rule order), mirroring TCP.
    for cidr in exclude_cidrs {
        commands.push(idempotent_append(
            binary,
            "mangle",
            "FERRUM_MESH_UDP_OUTBOUND",
            &format!("-p udp -d {cidr} -j RETURN"),
        ));
    }
    for port in &config.exclude_ports {
        commands.push(idempotent_append(
            binary,
            "mangle",
            "FERRUM_MESH_UDP_OUTBOUND",
            &format!("-p udp --dport {port} -j RETURN"),
        ));
    }
    // NOTE: no proxy-UID (`-m owner --uid-owner`) self-exclusion in THIS chain.
    // `-m owner` matches only locally-generated packets, so it is valid only in an
    // OUTPUT-context chain — and this OUTBOUND chain is reached from PREROUTING
    // (TPROXY is PREROUTING-only). The proxy's own UDP egress is locally generated,
    // so its self-exclusion lives in the OUTPUT MARK chain below (the owner-match
    // RETURN), not here.
    for rule in &outbound_tproxy_rules {
        commands.push(idempotent_append(
            binary,
            "mangle",
            "FERRUM_MESH_UDP_OUTBOUND",
            rule,
        ));
    }

    // OUTPUT MARK chain population (codex r6): the pod's OWN locally-generated UDP
    // egress goes OUTPUT -> POSTROUTING and NEVER hits PREROUTING, so the OUTBOUND
    // TPROXY chain above (reached only from PREROUTING) never sees it. This chain —
    // jumped from `mangle OUTPUT` (added below) — MARKs that egress with the same
    // fwmark the PREROUTING TPROXY rules use, so the fwmark `ip rule` (priority
    // <P> -> table <T>) + `ip route add local ... dev lo table <T>` reroute the
    // marked datagram to loopback, where it re-enters the INPUT path, traverses
    // PREROUTING a single time, and is captured by the mark-match TPROXY rule
    // (added below). It uses MARK, NOT TPROXY, because TPROXY is invalid for
    // locally-generated (OUTPUT) packets. The chain order is:
    //   1. `-m mark --mark <mark>/<mask> -j RETURN` — never re-mark an already-
    //      marked packet (anti-loop belt-and-suspenders; the `local` route diverts
    //      the looped datagram to the INPUT side so OUTPUT is hit once, but this
    //      guard is the canonical safety rail).
    //   2. proxy-UID `-m owner --uid-owner <uid> -j RETURN` — exclude the proxy's
    //      OWN egress so it is neither captured nor looped. Owner-match is valid
    //      here precisely because OUTPUT sees the originating socket (it is invalid
    //      in PREROUTING, which is why the OUTBOUND chain has no owner RETURN).
    //   3. the same exclude-CIDR / exclude-port RETURNs as the OUTBOUND chain.
    //   4. the MARK rules derived from the SAME outbound selectors as the TPROXY
    //      rules AND carrying the SAME `! --dst-type LOCAL` egress scope (codex r9),
    //      so OUTPUT capture scoping matches PREROUTING capture scoping exactly.
    //      The dst-type scope is what keeps pod-to-self / loopback (`--dst-type
    //      LOCAL` in OUTPUT) OUT of the mark set so it is never fwmark-rerouted to
    //      `lo` and TPROXY-captured — only genuine egress to other hosts is marked.
    //      The proxy's OWN egress is separately excluded by the owner RETURN above;
    //      the dst-type scope additionally covers a NON-proxy local destination
    //      (another UID's loopback / self UDP) the owner RETURN cannot.
    // The chain is populated regardless of whether any selector matched: if it is
    // empty of MARK rules nothing is marked, and the OUTPUT jump below is a no-op.
    commands.push(idempotent_append(
        binary,
        "mangle",
        "FERRUM_MESH_UDP_OUTPUT_MARK",
        &format!("-m mark --mark {mark_arg} -j RETURN"),
    ));
    if let Some(uid) = config.proxy_uid {
        commands.push(idempotent_append(
            binary,
            "mangle",
            "FERRUM_MESH_UDP_OUTPUT_MARK",
            &format!("-m owner --uid-owner {uid} -j RETURN"),
        ));
    }
    for cidr in exclude_cidrs {
        commands.push(idempotent_append(
            binary,
            "mangle",
            "FERRUM_MESH_UDP_OUTPUT_MARK",
            &format!("-p udp -d {cidr} -j RETURN"),
        ));
    }
    for port in &config.exclude_ports {
        commands.push(idempotent_append(
            binary,
            "mangle",
            "FERRUM_MESH_UDP_OUTPUT_MARK",
            &format!("-p udp --dport {port} -j RETURN"),
        ));
    }
    for rule in &outbound_mark_rules {
        commands.push(idempotent_append(
            binary,
            "mangle",
            "FERRUM_MESH_UDP_OUTPUT_MARK",
            rule,
        ));
    }

    // Inbound UDP chain — created, flushed, populated, and (below) jumped from
    // PREROUTING when `emit_inbound` is set. Co-located here so all inbound
    // wiring lives behind one gate. Teardown reaps the chain UNCONDITIONALLY so a
    // pod upgraded from a prior version that DID install it is cleaned up.
    if emit_inbound {
        commands.push(idempotent_new_chain(
            binary,
            "mangle",
            "FERRUM_MESH_UDP_INBOUND",
        ));
        commands.push(flush_chain(binary, "mangle", "FERRUM_MESH_UDP_INBOUND"));
        // Inbound exclusions before the catch-all TPROXY (RETURN must precede it,
        // mirroring the TCP inbound chain).
        for port in &config.exclude_inbound_ports {
            commands.push(idempotent_append(
                binary,
                "mangle",
                "FERRUM_MESH_UDP_INBOUND",
                &format!("-p udp --dport {port} -j RETURN"),
            ));
        }
        // Inbound catch-all scoped to a LOCAL destination (the pod's own IP) so it
        // captures ONLY genuinely-inbound UDP — never pod egress that fell through
        // the OUTBOUND chain. The complement of the OUTBOUND chain's
        // `! --dst-type LOCAL`, keeping the two PREROUTING chains direction-disjoint
        // without knowing the pod IP (codex r2).
        commands.push(idempotent_append(
            binary,
            "mangle",
            "FERRUM_MESH_UDP_INBOUND",
            &format!("-p udp -m addrtype --dst-type LOCAL {tproxy_jump}"),
        ));
    }

    // Transparent-routing plumbing: raw `ip` commands (NOT iptables). The fwmark
    // selector must match the `--tproxy-mark` value above so marked datagrams are
    // steered to the local-delivery table.
    //
    // INSTALLED BEFORE THE PREROUTING JUMPS (codex r5 finding #3). The jumps are
    // what start steering UDP into the chains; if `ip rule`/`ip route` failed
    // AFTER the jumps were appended, the injector's trap-less `set -e` init script
    // would leave the pod with TPROXY chains live but no policy routing — the
    // half-installed black-hole. Emitting routing first means a routing failure
    // aborts the script BEFORE any capture is wired (the chains/rules above are
    // inert until the jumps below are appended).
    //
    // FAIL CLOSED (codex r2): TPROXY local delivery is USELESS without this
    // routing, so the load-bearing ADD commands are NOT `|| true` — under the
    // (set -e) setup script a failed add aborts, rather than leaving a pod that
    // is "ready" but silently black-holes captured UDP. (`command -v ip` was
    // already asserted FATALLY at the top of this function, before any UDP rule,
    // so the adds run only when `ip` exists.) Only the delete-before-add stays
    // best-effort (`|| true`).
    //
    // Idempotency: `ip rule add` APPENDS, so a retry (e.g. a node-agent fallback
    // crash before cleanup ran) would stack a duplicate rule. We assign an
    // EXPLICIT priority and delete-by-priority before adding; cleanup deletes the
    // same exact priority. The local route is likewise delete-before-add so a
    // rerun never errors on an already-present route.
    let (ip, local_route) = match family {
        CidrFamily::V4 => ("ip", "local 0.0.0.0/0 dev lo"),
        CidrFamily::V6 => ("ip -6", "local ::/0 dev lo"),
    };
    // Delete the prior fwmark rule by its STABLE Ferrum-owned priority + table
    // ONLY — NOT keyed on the mark value (codex r4). The Ferrum-owned priority
    // (`TPROXY_ROUTE_RULE_PRIORITY`) and table (`TPROXY_ROUTE_TABLE`) are fixed,
    // but `FERRUM_MESH_TPROXY_MARK` is operator-overridable: if the mark changed
    // since a prior run, a delete keyed on the NEW `fwmark <mark>` selector would
    // not match the OLD mark's priority-100 rule, leaving a stale selector that
    // keeps routing the old mark into table 33133. Deleting by priority + table
    // (mark-independent, exactly as the cleanup teardown does) removes whichever
    // mark the prior rule carried before the add installs the current one. Stays
    // best-effort (`|| true`): an already-absent rule must not abort `set -e`.
    commands.push(ip_delete_best_effort(&format!(
        "{ip} rule del priority {TPROXY_ROUTE_RULE_PRIORITY} lookup {TPROXY_ROUTE_TABLE}"
    )));
    commands.push(format!(
        "{ip} rule add priority {TPROXY_ROUTE_RULE_PRIORITY} fwmark 0x{mark:x}/0x{TPROXY_MARK_MASK:x} lookup {TPROXY_ROUTE_TABLE}"
    ));
    commands.push(ip_delete_best_effort(&format!(
        "{ip} route del {local_route} table {TPROXY_ROUTE_TABLE}"
    )));
    commands.push(format!(
        "{ip} route add {local_route} table {TPROXY_ROUTE_TABLE}"
    ));

    // PREROUTING jumps + the locally-generated reinjection capture, all LAST
    // (codex r5 finding #3): these start steering UDP into the now-fully-built
    // chains, and the routing above is already installed, so there is no window
    // where TPROXY is wired without policy routing.
    //
    // (1) REINJECT chain: the mark-match `-j TPROXY` rule, populated then jumped
    // from PREROUTING FIRST (codex r6). The OUTPUT MARK chain marks the pod's OWN
    // egress; the fwmark `ip rule` + `local ... dev lo` route then reroute that
    // marked datagram to loopback, where it re-enters the INPUT path and traverses
    // PREROUTING. This rule captures the rerouted datagram by its MARK (the only
    // reliable selector — TPROXY/loopback do NOT rewrite the header, so the
    // datagram still carries its ORIGINAL remote destination and would also match
    // the dst-based OUTBOUND chain). Because xt_TPROXY returns NF_ACCEPT and ends
    // PREROUTING traversal, jumping into this chain BEFORE the OUTBOUND/INBOUND
    // chain jumps guarantees the rerouted datagram is TPROXY'd exactly once and
    // never double-processed by the dst-based chains. It carries the SAME mark
    // (`--tproxy-mark`) so TPROXY re-stamps the mark the local-delivery route
    // already used. The chain is inert for ordinary inbound/forwarded UDP (which
    // carries no Ferrum mark) — only the OUTPUT-marked, rerouted datagrams match.
    commands.push(idempotent_append(
        binary,
        "mangle",
        "FERRUM_MESH_UDP_REINJECT",
        &format!("-p udp -m mark --mark {mark_arg} {tproxy_jump}"),
    ));
    commands.push(idempotent_append(
        binary,
        "mangle",
        "PREROUTING",
        "-p udp -j FERRUM_MESH_UDP_REINJECT",
    ));
    // (2) The OUTBOUND jump is installed BEFORE the INBOUND jump so pod EGRESS is
    // matched/routed first: the inbound catch-all (xt_TPROXY returns NF_ACCEPT,
    // ending traversal) must not swallow egress and bypass the outbound
    // include/exclude/CIDR/port rules. The two chains are also destination-scoped
    // (`! --dst-type LOCAL` outbound, `--dst-type LOCAL` inbound) so each captures
    // only its own direction regardless of order; the ordering is the
    // belt-and-suspenders mirror of the TCP chains (codex r2). These see only
    // genuinely PREROUTING-visible UDP (forwarded / inbound-to-pod), NOT the pod's
    // own locally-generated egress — that is the OUTPUT MARK chain's job (1).
    commands.push(idempotent_append(
        binary,
        "mangle",
        "PREROUTING",
        "-p udp -j FERRUM_MESH_UDP_OUTBOUND",
    ));
    // The INBOUND jump is emitted when `emit_inbound` is set so pod-destined UDP
    // cannot bypass mesh identity and authorization by flowing directly to the app.
    if emit_inbound {
        commands.push(idempotent_append(
            binary,
            "mangle",
            "PREROUTING",
            "-p udp -j FERRUM_MESH_UDP_INBOUND",
        ));
    }
    // (3) The OUTPUT jump into the MARK-only chain (codex r6). This is the path for
    // the pod's OWN locally-generated UDP egress (OUTPUT -> POSTROUTING never hits
    // PREROUTING). The chain MARKs (does NOT TPROXY — TPROXY is invalid in OUTPUT
    // and jumping into a `-j TPROXY` chain from OUTPUT can fail iptables setup
    // outright); the fwmark route reroutes to lo and (1) above completes the
    // capture loop: OUTPUT-MARK -> lo-reroute (fwmark `ip rule` -> local route) ->
    // PREROUTING mark-match TPROXY -> the Stage 3 transparent UDP socket.
    commands.push(idempotent_append(
        binary,
        "mangle",
        "OUTPUT",
        "-p udp -j FERRUM_MESH_UDP_OUTPUT_MARK",
    ));

    commands
}

/// Wrap a best-effort `ip` DELETE (the idempotence delete-before-add and the
/// cleanup teardown) with `|| true` so an already-absent rule/route never aborts
/// the (`set -e`) script. NOTE: this is for DELETES only — the load-bearing
/// setup ADDs deliberately do NOT use it (they must fail closed; see
/// `udp_tproxy_commands_for_family`). A `command -v ip` preflight is asserted
/// separately and fatally by callers before the load-bearing adds.
fn ip_delete_best_effort(cmd: &str) -> String {
    format!("{cmd} 2>/dev/null || true")
}

fn iptables_script(
    v4_commands: &[String],
    v6_commands: &[String],
    ip6tables_mode: Ip6TablesMode,
    emit_required_mode_preflight: bool,
) -> String {
    let mut chunks = Vec::new();
    if emit_required_mode_preflight
        && !v6_commands.is_empty()
        && ip6tables_mode == Ip6TablesMode::Required
    {
        chunks.push(format!(
            "command -v ip6tables >/dev/null 2>&1 || {{ echo \"ip6tables is required for IPv6 mesh capture\" >&2; exit 1; }}\n\
             ip6tables -t nat -w {XTABLES_LOCK_WAIT_SECONDS} -L >/dev/null 2>&1 || {{ echo \"ip6tables nat table is required for IPv6 mesh capture\" >&2; exit 1; }}"
        ));
    }
    if !v4_commands.is_empty() {
        chunks.push(v4_commands.join("\n"));
    }
    if !v6_commands.is_empty() {
        let v6_script = v6_commands.join("\n");
        match ip6tables_mode {
            Ip6TablesMode::Auto => chunks.push(format!(
                "if command -v ip6tables >/dev/null 2>&1; then\n  if ip6tables -t nat -w {XTABLES_LOCK_WAIT_SECONDS} -L >/dev/null 2>&1; then\n    {}\n  else\n    echo \"ip6tables nat table unavailable; skipping IPv6 mesh capture rules\"\n  fi\nelse\n  echo \"ip6tables not found; skipping IPv6 mesh capture rules\"\nfi",
                v6_script.replace('\n', "\n    ")
            )),
            Ip6TablesMode::Required => chunks.push(v6_script),
            Ip6TablesMode::Disabled => {
                debug_assert!(
                    v6_commands.is_empty(),
                    "IptablesPlan::for_config must clear v6 commands when ip6tables is disabled"
                );
            }
        }
    }
    chunks.join("\n")
}

/// Like [`iptables_script`], but the IPv6 availability probe checks the
/// **`mangle`** table (where the UDP TPROXY chains live) rather than `nat`.
/// A host with `mangle` support but no `nat` table must still run the UDP v6
/// rules — probing `nat` would wrongly skip them. Used by
/// [`IptablesPlan::udp_setup_script`] for the Ambient per-pod-netns producer.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn udp_iptables_script(
    v4_commands: &[String],
    v6_commands: &[String],
    ip6tables_mode: Ip6TablesMode,
    emit_required_mode_preflight: bool,
) -> String {
    let mut chunks = Vec::new();
    if emit_required_mode_preflight
        && !v6_commands.is_empty()
        && ip6tables_mode == Ip6TablesMode::Required
    {
        chunks.push(format!(
            "command -v ip6tables >/dev/null 2>&1 || {{ echo \"ip6tables is required for IPv6 mesh UDP capture\" >&2; exit 1; }}\n\
             ip6tables -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -L >/dev/null 2>&1 || {{ echo \"ip6tables mangle table is required for IPv6 mesh UDP capture\" >&2; exit 1; }}"
        ));
    }
    if !v4_commands.is_empty() {
        chunks.push(v4_commands.join("\n"));
    }
    if !v6_commands.is_empty() {
        let v6_script = v6_commands.join("\n");
        match ip6tables_mode {
            Ip6TablesMode::Auto => chunks.push(format!(
                "if command -v ip6tables >/dev/null 2>&1; then\n  if ip6tables -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -L >/dev/null 2>&1; then\n    {}\n  else\n    echo \"ip6tables mangle table unavailable; skipping IPv6 mesh UDP capture rules\"\n  fi\nelse\n  echo \"ip6tables not found; skipping IPv6 mesh UDP capture rules\"\nfi",
                v6_script.replace('\n', "\n    ")
            )),
            Ip6TablesMode::Required => chunks.push(v6_script),
            Ip6TablesMode::Disabled => {
                debug_assert!(
                    v6_commands.is_empty(),
                    "udp_only_for_config must clear v6 commands when ip6tables is disabled"
                );
            }
        }
    }
    chunks.join("\n")
}

/// Wrap a single IPv6 command behind an `ip6tables` availability probe on the
/// given table (`nat` for the TCP capture chains, `mangle` for the UDP TPROXY
/// chains), echoing and skipping when `ip6tables` or that table is unavailable.
/// Shared by the Ambient producer's UDP teardown and the node-agent fallback
/// cleanup so the probe shape can never drift between them.
pub(crate) fn ip6tables_probe_guard(cmd: &str, table: &str) -> String {
    format!(
        "if command -v ip6tables >/dev/null 2>&1; then\n  if ip6tables -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -L >/dev/null 2>&1; then\n    {cmd}\n  else\n    echo \"ip6tables {table} table unavailable; skipping IPv6 mesh capture rules\"\n  fi\nelse\n  echo \"ip6tables not found; skipping IPv6 mesh capture rules\"\nfi"
    )
}

/// Strict optional-ip6tables wrapper for the guarded→live readiness transition.
/// Missing tooling / an unavailable kernel table is optional, but resource and
/// command errors must propagate so callers cannot report success while a stale
/// OUTPUT jump remains active.
fn ip6tables_strict_probe_guard(commands: &str, table: &str) -> String {
    format!(
        "if command -v ip6tables >/dev/null 2>&1; then\n  if ip6tables -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -L >/dev/null 2>&1; then\n    {commands}\n  else\n    status=$?\n    if [ \"$status\" -eq 3 ]; then\n      echo \"ip6tables {table} table unavailable; skipping IPv6 mesh capture rules\"\n    else\n      echo \"ip6tables {table} probe failed with status $status\" >&2\n      exit \"$status\"\n    fi\n  fi\nelse\n  echo \"ip6tables not found; skipping IPv6 mesh capture rules\"\nfi"
    )
}

/// The UDP-only command list for one address family, filtering include/exclude
/// CIDRs to that family exactly like [`commands_for_family`] before delegating
/// to the shared `udp_tproxy_commands_for_family`. This is what keeps the
/// Ambient producer's UDP rules byte-identical to the injector's UDP rules.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn udp_only_commands_for_family(config: &CaptureConfig, family: CidrFamily) -> Vec<String> {
    let binary = match family {
        CidrFamily::V4 => "iptables",
        CidrFamily::V6 => "ip6tables",
    };
    let include_cidrs: Vec<&str> = config
        .include_cidrs
        .iter()
        .filter(|cidr| cidr_family(cidr) == Some(family))
        .map(String::as_str)
        .collect();
    let exclude_cidrs: Vec<&str> = config
        .exclude_cidrs
        .iter()
        .filter(|cidr| cidr_family(cidr) == Some(family))
        .map(String::as_str)
        .collect();
    // OUTBOUND-ONLY for the Ambient producer: it installs rules inside every
    // enrolled pod netns (incl. destination pods), where capturing inbound
    // `--dst-type LOCAL` UDP would black-hole the HBONE relay's delivery to the
    // local app and the source pod's return-path reply (codex).
    udp_tproxy_commands_for_family(
        binary,
        config,
        family,
        &include_cidrs,
        &exclude_cidrs,
        false,
    )
}

fn cleanup_commands_for(binary: &str, udp_capture_enabled: bool) -> CleanupCommands {
    let iptables = vec![
        // Step 1: remove jump rules from built-in chains
        idempotent_delete(binary, "nat", "OUTPUT", "-p tcp -j FERRUM_MESH_OUTBOUND"),
        idempotent_delete(binary, "nat", "PREROUTING", "-p tcp -j FERRUM_MESH_INBOUND"),
        // Step 2: flush custom chains
        flush_chain(binary, "nat", "FERRUM_MESH_INBOUND"),
        flush_chain(binary, "nat", "FERRUM_MESH_OUTBOUND"),
        // Step 3: delete custom chains (must be empty first)
        delete_chain(binary, "nat", "FERRUM_MESH_INBOUND"),
        delete_chain(binary, "nat", "FERRUM_MESH_OUTBOUND"),
    ];

    let mut combined = CleanupCommands {
        iptables,
        ip_routing: Vec::new(),
    };

    // UDP TPROXY teardown is GATED on `udp_capture_enabled` HERE: when this
    // install never emitted UDP rules, the normal shutdown/setup-failure cleanup
    // must not touch routing state it never created. (The node-agent runs a
    // SEPARATE UNCONDITIONAL pre-setup teardown via [`udp_teardown_for`] to reap
    // stale state from a prior UDP-enabled-then-crashed run — codex r4.)
    if udp_capture_enabled {
        let udp = udp_teardown_for(binary);
        combined.iptables.extend(udp.iptables);
        combined.ip_routing.extend(udp.ip_routing);
    }

    combined
}

/// The EXACT Ferrum-owned UDP TPROXY teardown for one `iptables`/`ip6tables`
/// family, split into the table teardown (`iptables`) and the raw `ip` routing
/// teardown (`ip_routing`). Contains ONLY UDP-specific state — never the TCP nat
/// chains — so it is safe to run UNCONDITIONALLY before setup to reap stale state
/// from a prior UDP-enabled run, without disturbing the TCP chains setup is about
/// to (re)build. Every command targets an EXACT Ferrum-owned object (mangle
/// chains by name, the fwmark rule by its stable priority, the route by its exact
/// table spec) and is idempotent/best-effort, so running it when no UDP state
/// exists is a no-op.
fn udp_capture_teardown_for(binary: &str) -> CleanupCommands {
    let family = if binary == "ip6tables" {
        CidrFamily::V6
    } else {
        CidrFamily::V4
    };

    // mangle chain teardown: jumps first, then flush, then delete. The OUTPUT MARK
    // path (codex r6) adds a `mangle OUTPUT -j FERRUM_MESH_UDP_OUTPUT_MARK` jump and
    // a `mangle PREROUTING -j FERRUM_MESH_UDP_REINJECT` jump that must also be torn
    // down (the legacy "no OUTPUT jump" note is obsolete). Every target is an EXACT
    // Ferrum-owned object (chain by name, jump by exact `-j <chain>` spec —
    // mark-independent), so this teardown is fully mark-independent and can run
    // UNCONDITIONALLY pre-setup to reap stale state even across a changed
    // `FERRUM_MESH_TPROXY_MARK` (the mark-match rule lives INSIDE the reinject
    // chain, which is reaped by name, never as a bare PREROUTING rule). These are
    // ip6tables-TABLE commands, so for IPv6 the node-agent guards them behind its
    // `ip6tables` availability probe.
    let iptables = vec![
        idempotent_delete(
            binary,
            "mangle",
            "PREROUTING",
            "-p udp -j FERRUM_MESH_UDP_REINJECT",
        ),
        idempotent_delete(
            binary,
            "mangle",
            "PREROUTING",
            "-p udp -j FERRUM_MESH_UDP_INBOUND",
        ),
        idempotent_delete(
            binary,
            "mangle",
            "PREROUTING",
            "-p udp -j FERRUM_MESH_UDP_OUTBOUND",
        ),
        idempotent_delete(
            binary,
            "mangle",
            "OUTPUT",
            "-p udp -j FERRUM_MESH_UDP_OUTPUT_MARK",
        ),
        flush_chain(binary, "mangle", "FERRUM_MESH_UDP_INBOUND"),
        flush_chain(binary, "mangle", "FERRUM_MESH_UDP_OUTBOUND"),
        flush_chain(binary, "mangle", "FERRUM_MESH_UDP_OUTPUT_MARK"),
        flush_chain(binary, "mangle", "FERRUM_MESH_UDP_REINJECT"),
        delete_chain(binary, "mangle", "FERRUM_MESH_UDP_INBOUND"),
        delete_chain(binary, "mangle", "FERRUM_MESH_UDP_OUTBOUND"),
        delete_chain(binary, "mangle", "FERRUM_MESH_UDP_OUTPUT_MARK"),
        delete_chain(binary, "mangle", "FERRUM_MESH_UDP_REINJECT"),
    ];

    // Remove ONLY the EXACT Ferrum-owned routing rule + route from the
    // Ferrum-specific table — never `ip rule del lookup <table>` (would drop an
    // unrelated rule pointing at the table) and never `ip route flush table`
    // (would wipe any co-resident route, e.g. an Istio table). Delete the rule by
    // its explicit priority (mark-independent) and the route by its exact spec.
    //
    // These are RAW `ip`/`ip -6` commands — independent of `iptables`/`ip6tables`.
    // They go in `ip_routing` so the node-agent emits them UNCONDITIONALLY: gating
    // the `ip -6 rule/route del` behind an `ip6tables` probe (codex r3) would leak
    // the fwmark rule + local route whenever `ip6tables` is missing, and marked
    // UDP would keep diverting after shutdown even though `ip -6` could have
    // removed it.
    let (ip, local_route) = match family {
        CidrFamily::V6 => ("ip -6", "local ::/0 dev lo"),
        CidrFamily::V4 => ("ip", "local 0.0.0.0/0 dev lo"),
    };
    // Cleanup deletes stay best-effort (`|| true`): teardown must never fail on
    // already-absent routing state or a missing `ip` binary.
    let ip_routing = vec![
        ip_delete_best_effort(&format!(
            "{ip} rule del priority {TPROXY_ROUTE_RULE_PRIORITY} lookup {TPROXY_ROUTE_TABLE}"
        )),
        ip_delete_best_effort(&format!(
            "{ip} route del {local_route} table {TPROXY_ROUTE_TABLE}"
        )),
    ];

    CleanupCommands {
        iptables,
        ip_routing,
    }
}

fn udp_fail_closed_chain_teardown_for(binary: &str, chain: &str) -> Vec<String> {
    vec![
        // A prior interrupted switch can leave duplicate jumps. Removing only
        // one before flushing the chain would keep selected egress pointed at an
        // empty/black-holing guard, so final cleanup uses the same strict loop as
        // the guarded-to-live transition.
        udp_strict_output_jump_release_for(binary, chain),
        flush_chain(binary, "mangle", chain),
        delete_chain(binary, "mangle", chain),
    ]
}

fn udp_fail_closed_teardown_for(binary: &str) -> Vec<String> {
    let mut commands = udp_fail_closed_chain_teardown_for(binary, UDP_FAIL_CLOSED_CHAIN_A);
    commands.extend(udp_fail_closed_chain_teardown_for(
        binary,
        UDP_FAIL_CLOSED_CHAIN_B,
    ));
    commands
}

/// Strict transition from guarded to live capture. The best-effort teardown
/// helpers intentionally hide missing state, but readiness must surface a
/// deletion failure so the producer cannot report success while still dropping
/// its workload's selected UDP egress.
fn udp_fail_closed_release_for(binary: &str) -> Vec<String> {
    [UDP_FAIL_CLOSED_CHAIN_A, UDP_FAIL_CLOSED_CHAIN_B]
        .into_iter()
        .flat_map(|chain| {
            [
                udp_strict_output_jump_release_for(binary, chain),
                flush_chain(binary, "mangle", chain),
                delete_chain(binary, "mangle", chain),
            ]
        })
        .collect()
}

fn udp_strict_output_jump_release_for(binary: &str, chain: &str) -> String {
    udp_strict_jump_release_for(binary, "OUTPUT", chain)
}

/// Strictly remove EVERY jump into `chain` from the built-in `hook` chain in the
/// `mangle` table. Shared by the pod-netns guards (hook `OUTPUT`, where a pod's
/// own egress is locally generated) and the host-netns guard + capture chains
/// (hook `PREROUTING`, where an enrolled pod's egress is FORWARDED and never
/// traverses `OUTPUT`). Only an absent chain (`-S` status 1) is tolerated; any
/// other status is a genuine xtables error that aborts, so a caller can never
/// report a completed release while a jump is still live.
fn udp_strict_jump_release_for(binary: &str, hook: &str, chain: &str) -> String {
    let jump = format!("-p udp -j {chain}");
    format!(
        "if {binary} -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -S {chain} >/dev/null 2>&1; then\n  while true; do\n    if {binary} -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -C {hook} {jump} 2>/dev/null; then\n      {binary} -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -D {hook} {jump}\n    else\n      status=$?\n      if [ \"$status\" -eq 1 ]; then\n        break\n      fi\n      echo \"{binary} could not check {hook} jump {chain} (status $status)\" >&2\n      exit \"$status\"\n    fi\n  done\nelse\n  status=$?\n  if [ \"$status\" -ne 1 ]; then\n    echo \"{binary} could not inspect UDP fail-closed guard chain {chain} before release (status $status)\" >&2\n    exit \"$status\"\n  fi\nfi"
    )
}

/// Full UDP teardown used by node-agent cleanup, producer removal, and disabled
/// stale-state cleanup. It removes both fail-closed guard generations and the
/// normal TPROXY/routing state.
fn udp_teardown_for(binary: &str) -> CleanupCommands {
    let capture = udp_capture_teardown_for(binary);
    // Remove the normal capture path first while any retained DROP guard still
    // protects selected egress. Guard removal is strict and comes last: a
    // transient resource error can then leave the workload fail-closed, but can
    // never prevent cleanup from detaching a socketless TPROXY path.
    let mut iptables = capture.iptables;
    iptables.extend(udp_fail_closed_teardown_for(binary));
    CleanupCommands {
        iptables,
        ip_routing: capture.ip_routing,
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Host-network UDP capture (issue #3288)
// ───────────────────────────────────────────────────────────────────────────
//
// The pod-netns generator above splits inbound from outbound by DESTINATION
// ADDRESS TYPE, which is only meaningful inside a pod's own namespace. The host
// path uses a different, exact discriminator: the INGRESS INTERFACE.
//
// In the host network namespace an enrolled pod's traffic is visible in three
// disjoint ways, and only one of them is workload-originated egress:
//
//  1. **Pod egress** enters the host namespace on THAT POD's host-side interface
//     (the veth peer) and traverses `mangle PREROUTING` with
//     `skb->dev == <pod interface>`. This is what the host path captures.
//  2. **Traffic destined for a pod** arrives on the NODE UPLINK, traverses
//     `PREROUTING` with `skb->dev == <uplink>`, and is then FORWARDED out the
//     pod interface. It never matches an `-i <pod interface>` rule, so inbound
//     UDP is untouched — no `--dst-type LOCAL` guesswork required.
//  3. **The node's own traffic** (kubelet, CNI, the mesh proxy's relay egress,
//     DNS, anything `hostNetwork`) is locally generated and traverses `OUTPUT`,
//     never `PREROUTING`. The host path installs NO `mangle OUTPUT` chain at
//     all, so host traffic is structurally incapable of being captured. This is
//     the load-bearing difference from the pod-netns generator, which DOES
//     install an OUTPUT MARK chain (correct there, because the only locally
//     generated traffic in a pod netns is the workload's).
//
// Everything else follows the pod path: TPROXY in `mangle` delivers without
// rewriting the destination, so the consuming listener recovers the original
// destination from the `IP_RECVORIGDSTADDR` cmsg, and transparent local delivery
// needs the fwmark `ip rule` + `local` route (installed BEFORE the jump, and
// fatally requiring `ip`, so the half-state of TPROXY-without-routing can never
// exist).

/// Per-family host UDP capture rules. `ifaces` is the set of host-side
/// interfaces owned by enrolled pods; every capture rule carries `-i <iface>`.
///
/// An EMPTY `ifaces` set is valid and meaningful: the chain, routing, and the
/// stable `PREROUTING` jump are still installed, but the chain contains only
/// exclusion RETURNs, so nothing is captured. That keeps reconciliation a pure
/// flush-and-repopulate of one chain (the jump never moves), which is what makes
/// pod add/remove atomic from the datapath's point of view.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn host_udp_tproxy_commands_for_family(
    binary: &str,
    config: &CaptureConfig,
    family: CidrFamily,
    include_cidrs: &[&str],
    exclude_cidrs: &[&str],
    ifaces: &[String],
) -> Vec<String> {
    let selectors = udp_outbound_selectors_for_family(config, family, include_cidrs);
    if selectors.is_empty() {
        // A pure cross-family CIDR skip: emit NO state for this family rather
        // than an inert chain + routing, matching `udp_tproxy_commands_for_family`.
        return Vec::new();
    }

    let mark = config.tproxy_mark;
    let mark_arg = format!("0x{mark:x}/0x{TPROXY_MARK_MASK:x}");
    let tproxy_jump = format!(
        "-j TPROXY --on-port {} --tproxy-mark {mark_arg}",
        config.udp_outbound_port
    );

    let mut commands = vec![
        // FAIL CLOSED before any rule: transparent local delivery is useless
        // without the `ip rule`/`ip route local` plumbing, so an image without
        // iproute2 must install NOTHING rather than a silent black hole.
        "command -v ip >/dev/null 2>&1 || { echo \"iproute2 (ip) is required for UDP TPROXY transparent routing\" >&2; exit 1; }"
            .to_string(),
        idempotent_new_chain(binary, "mangle", UDP_HOST_CAPTURE_CHAIN),
        // Flush before populating: the per-rule `-C ... || -A` guard is an EXACT
        // match, so a changed port/mark/interface set would append a new rule
        // BEHIND the stale one and the stale one would keep winning. Flushing is
        // also what makes reconciliation of the enrolled-pod set correct — a
        // removed pod's rule disappears instead of lingering.
        flush_chain(binary, "mangle", UDP_HOST_CAPTURE_CHAIN),
    ];

    // Exclusions first (RETURN wins by rule order), mirroring the pod path.
    // These are interface-independent: an excluded destination is excluded for
    // every enrolled pod.
    for cidr in exclude_cidrs {
        commands.push(idempotent_append(
            binary,
            "mangle",
            UDP_HOST_CAPTURE_CHAIN,
            &format!("-p udp -d {cidr} -j RETURN"),
        ));
    }
    for port in &config.exclude_ports {
        commands.push(idempotent_append(
            binary,
            "mangle",
            UDP_HOST_CAPTURE_CHAIN,
            &format!("-p udp --dport {port} -j RETURN"),
        ));
    }
    // NOTE: no `-m owner --uid-owner` self-exclusion. Owner-match is only valid
    // for locally generated packets (an OUTPUT-context chain), and this chain is
    // reached from PREROUTING. It is also unnecessary: the proxy's own relay
    // egress is locally generated and therefore never traverses PREROUTING at
    // all, and it does not arrive on an enrolled pod's interface.
    for iface in ifaces {
        for selector in &selectors {
            commands.push(idempotent_append(
                binary,
                "mangle",
                UDP_HOST_CAPTURE_CHAIN,
                &format!("-i {iface} {selector} {tproxy_jump}"),
            ));
        }
    }

    // Transparent-routing plumbing on the HOST-owned table/priority, installed
    // BEFORE the jump so a routing failure aborts the `set -e` script while the
    // chain is still unreachable.
    let (ip, local_route) = match family {
        CidrFamily::V4 => ("ip", "local 0.0.0.0/0 dev lo"),
        CidrFamily::V6 => ("ip -6", "local ::/0 dev lo"),
    };
    commands.push(ip_delete_best_effort(&format!(
        "{ip} rule del priority {TPROXY_HOST_ROUTE_RULE_PRIORITY} lookup {TPROXY_HOST_ROUTE_TABLE}"
    )));
    commands.push(format!(
        "{ip} rule add priority {TPROXY_HOST_ROUTE_RULE_PRIORITY} fwmark 0x{mark:x}/0x{TPROXY_MARK_MASK:x} lookup {TPROXY_HOST_ROUTE_TABLE}"
    ));
    commands.push(ip_delete_best_effort(&format!(
        "{ip} route del {local_route} table {TPROXY_HOST_ROUTE_TABLE}"
    )));
    commands.push(format!(
        "{ip} route add {local_route} table {TPROXY_HOST_ROUTE_TABLE}"
    ));

    // The single stable PREROUTING jump, LAST. It is deliberately NOT
    // interface-scoped: keeping the jump constant across reconciles means the
    // enrolled-pod set is changed by rebuilding the chain's CONTENTS, never by
    // adding/removing built-in-chain rules, so a crash mid-reconcile can only
    // leave a chain whose contents are a subset of the intended set — never an
    // orphaned jump into a chain nobody reaps. Interface scoping lives on the
    // TPROXY rules inside the chain; non-enrolled UDP falls through to RETURN.
    commands.push(idempotent_append(
        binary,
        "mangle",
        "PREROUTING",
        &format!("-p udp -j {UDP_HOST_CAPTURE_CHAIN}"),
    ));

    commands
}

/// Per-family host UDP fail-closed DROP guard chain contents. Mirrors the
/// capture chain's exclusions and selectors EXACTLY (so the guard never drops
/// traffic capture would have let through, and never lets through traffic
/// capture would have taken) but terminates in `-j DROP`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn host_udp_guard_chain_commands(
    binary: &str,
    chain: &str,
    config: &CaptureConfig,
    family: CidrFamily,
    include_cidrs: &[&str],
    exclude_cidrs: &[&str],
    ifaces: &[String],
) -> Vec<String> {
    let selectors = udp_outbound_selectors_for_family(config, family, include_cidrs);
    if selectors.is_empty() || ifaces.is_empty() {
        // Nothing this family/interface set would capture, so nothing to guard.
        return Vec::new();
    }
    // Strict reset of the inactive generation: treating an xtables resource
    // error as "already exists" could leave stale selectors in the replacement.
    let mut commands = vec![format!(
        "{binary} -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -N {chain} 2>/dev/null || \
         {binary} -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -F {chain}"
    )];
    for cidr in exclude_cidrs {
        commands.push(format!(
            "{binary} -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -A {chain} \
             -p udp -d {cidr} -j RETURN"
        ));
    }
    for port in &config.exclude_ports {
        commands.push(format!(
            "{binary} -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -A {chain} \
             -p udp --dport {port} -j RETURN"
        ));
    }
    for iface in ifaces {
        for selector in &selectors {
            commands.push(format!(
                "{binary} -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -A {chain} \
                 -i {iface} {selector} -j DROP"
            ));
        }
    }
    commands
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn host_udp_guard_commands_for_family(
    binary: &str,
    config: &CaptureConfig,
    family: CidrFamily,
    ifaces: &[String],
) -> Vec<String> {
    if !config.udp_capture_enabled {
        return Vec::new();
    }
    let include_cidrs: Vec<&str> = config
        .include_cidrs
        .iter()
        .filter(|cidr| cidr_family(cidr) == Some(family))
        .map(String::as_str)
        .collect();
    let exclude_cidrs: Vec<&str> = config
        .exclude_cidrs
        .iter()
        .filter(|cidr| cidr_family(cidr) == Some(family))
        .map(String::as_str)
        .collect();
    let build_a = host_udp_guard_chain_commands(
        binary,
        UDP_HOST_GUARD_CHAIN_A,
        config,
        family,
        &include_cidrs,
        &exclude_cidrs,
        ifaces,
    );
    if build_a.is_empty() {
        return Vec::new();
    }
    let build_b = host_udp_guard_chain_commands(
        binary,
        UDP_HOST_GUARD_CHAIN_B,
        config,
        family,
        &include_cidrs,
        &exclude_cidrs,
        ifaces,
    );
    udp_guard_switch_commands(
        binary,
        "PREROUTING",
        UDP_HOST_GUARD_CHAIN_A,
        UDP_HOST_GUARD_CHAIN_B,
        &build_a,
        &build_b,
    )
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn host_udp_commands_for_family(
    config: &CaptureConfig,
    family: CidrFamily,
    ifaces: &[String],
) -> Vec<String> {
    let binary = match family {
        CidrFamily::V4 => "iptables",
        CidrFamily::V6 => "ip6tables",
    };
    let include_cidrs: Vec<&str> = config
        .include_cidrs
        .iter()
        .filter(|cidr| cidr_family(cidr) == Some(family))
        .map(String::as_str)
        .collect();
    let exclude_cidrs: Vec<&str> = config
        .exclude_cidrs
        .iter()
        .filter(|cidr| cidr_family(cidr) == Some(family))
        .map(String::as_str)
        .collect();
    host_udp_tproxy_commands_for_family(
        binary,
        config,
        family,
        &include_cidrs,
        &exclude_cidrs,
        ifaces,
    )
}

/// The EXACT Ferrum-owned host UDP capture teardown for one family: the stable
/// `PREROUTING` jump, the capture chain, and the host-owned fwmark rule + local
/// route. Every target is addressed by an exact Ferrum-owned name/priority, so
/// this is safe to run unconditionally before setup to reap a prior generation's
/// state, and it can never touch the pod-netns objects (different chain names,
/// different table, different rule priority) or a co-resident CNI's routing.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn host_udp_capture_teardown_for(binary: &str) -> CleanupCommands {
    let family = if binary == "ip6tables" {
        CidrFamily::V6
    } else {
        CidrFamily::V4
    };
    let iptables = vec![
        idempotent_delete(
            binary,
            "mangle",
            "PREROUTING",
            &format!("-p udp -j {UDP_HOST_CAPTURE_CHAIN}"),
        ),
        flush_chain(binary, "mangle", UDP_HOST_CAPTURE_CHAIN),
        delete_chain(binary, "mangle", UDP_HOST_CAPTURE_CHAIN),
    ];
    let (ip, local_route) = match family {
        CidrFamily::V6 => ("ip -6", "local ::/0 dev lo"),
        CidrFamily::V4 => ("ip", "local 0.0.0.0/0 dev lo"),
    };
    let ip_routing = vec![
        ip_delete_best_effort(&format!(
            "{ip} rule del priority {TPROXY_HOST_ROUTE_RULE_PRIORITY} lookup {TPROXY_HOST_ROUTE_TABLE}"
        )),
        ip_delete_best_effort(&format!(
            "{ip} route del {local_route} table {TPROXY_HOST_ROUTE_TABLE}"
        )),
    ];
    CleanupCommands {
        iptables,
        ip_routing,
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn host_udp_guard_teardown_for(binary: &str) -> Vec<String> {
    [UDP_HOST_GUARD_CHAIN_A, UDP_HOST_GUARD_CHAIN_B]
        .into_iter()
        .flat_map(|chain| {
            [
                udp_strict_jump_release_for(binary, "PREROUTING", chain),
                flush_chain(binary, "mangle", chain),
                delete_chain(binary, "mangle", chain),
            ]
        })
        .collect()
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn host_udp_teardown_for(binary: &str) -> CleanupCommands {
    let capture = host_udp_capture_teardown_for(binary);
    // Detach the capture path first while any retained DROP guard still protects
    // enrolled egress; strict guard removal comes last so a transient xtables
    // error can leave the node fail-CLOSED but can never leave a socketless
    // TPROXY jump behind an already-released guard.
    let mut iptables = capture.iptables;
    iptables.extend(host_udp_guard_teardown_for(binary));
    CleanupCommands {
        iptables,
        ip_routing: capture.ip_routing,
    }
}

fn idempotent_new_chain(binary: &str, table: &str, chain: &str) -> String {
    format!("{binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -N {chain} 2>/dev/null || true")
}

fn idempotent_append(binary: &str, table: &str, chain: &str, rule: &str) -> String {
    format!(
        "{binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -C {chain} {rule} 2>/dev/null || {binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -A {chain} {rule}"
    )
}

/// Install one rule at position 1 even when the chain survived an earlier
/// generation. A simple `-C || -I` is not sufficient: if the rule already
/// exists below a REDIRECT, `-C` succeeds and leaves the safety rule dead. The
/// exact delete plus insert is idempotent and makes the documented "leads with"
/// contract true across guarded retries as well as a fresh chain.
fn idempotent_insert_first(binary: &str, table: &str, chain: &str, rule: &str) -> String {
    format!(
        "{binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -D {chain} {rule} 2>/dev/null || true; {binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -I {chain} 1 {rule}"
    )
}

fn idempotent_delete(binary: &str, table: &str, chain: &str, rule: &str) -> String {
    format!(
        "{binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -D {chain} {rule} 2>/dev/null || true"
    )
}

fn flush_chain(binary: &str, table: &str, chain: &str) -> String {
    format!("{binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -F {chain} 2>/dev/null || true")
}

fn delete_chain(binary: &str, table: &str, chain: &str) -> String {
    format!("{binary} -t {table} -w {XTABLES_LOCK_WAIT_SECONDS} -X {chain} 2>/dev/null || true")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tolerates_missing_cleanup_state(command: &str) -> bool {
        command.contains("|| true")
            || (command.contains("while true; do")
                && command.contains("FERRUM_UDP_FAIL_CLOSED_")
                && command.contains("if [ \"$status\" -eq 1 ]")
                && command.contains("exit \"$status\""))
    }

    #[test]
    fn iptables_plan_is_idempotent() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.proxy_uid = Some(DEFAULT_PROXY_UID);
        config.exclude_cidrs.push("10.0.0.0/8".to_string());
        config.exclude_ports.push(15020);

        let plan = IptablesPlan::for_config(&config).unwrap();

        assert!(plan.v4_commands.iter().any(|cmd| cmd.contains("-C OUTPUT")));
        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("--uid-owner 1337"))
        );
        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("--to-ports 15001"))
        );
    }

    #[test]
    fn udp_fail_closed_script_drops_udp_after_exclusions() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.udp_capture_enabled = true;
        config.exclude_cidrs = vec!["10.0.0.0/8".to_string()];
        config.exclude_ports = vec![53];

        let script = IptablesPlan::udp_fail_closed_script(&config);

        assert!(script.starts_with("set -e\n"));
        assert!(script.contains(UDP_FAIL_CLOSED_CHAIN_A));
        assert!(script.contains(UDP_FAIL_CLOSED_CHAIN_B));
        assert!(script.contains("-I OUTPUT 1 -p udp -j FERRUM_UDP_FAIL_CLOSED_"));
        assert!(!script.contains("FERRUM_MESH_UDP_OUTPUT_MARK"));
        assert!(script.contains("-p udp -d 10.0.0.0/8 -j RETURN"));
        assert!(script.contains("-p udp --dport 53 -j RETURN"));
        assert!(script.contains("-p udp -d 0.0.0.0/0 -m addrtype ! --dst-type LOCAL -j DROP"));
        // The active-guard swap (chain A currently active -> repopulate and
        // activate chain B, then release A) lives in the inner `-C OUTPUT ... -j A`
        // then-branch. Anchor on that probe so the assertion survives the outer
        // chain-existence guard (issue #2084) rather than the first `; then`.
        let a_active_probe =
            format!("-C OUTPUT -p udp -j {UDP_FAIL_CLOSED_CHAIN_A} 2>/dev/null; then\n");
        let active_branch = script
            .split_once(a_active_probe.as_str())
            .map(|(_, rest)| rest)
            .expect("alternating guard switch");
        let build_replacement = active_branch
            .find(&format!("-F {UDP_FAIL_CLOSED_CHAIN_B}"))
            .expect("replacement guard is populated");
        let insert_replacement = active_branch
            .find(&format!("-I OUTPUT 1 -p udp -j {UDP_FAIL_CLOSED_CHAIN_B}"))
            .expect("replacement guard is activated");
        let remove_previous = active_branch
            .find(&format!("-D OUTPUT -p udp -j {UDP_FAIL_CLOSED_CHAIN_A}"))
            .expect("previous guard is removed");
        assert!(build_replacement < insert_replacement && insert_replacement < remove_previous);
    }

    /// Issue #2084: on a fresh pod netns neither guard chain exists. The install
    /// must FIRST establish chain A's existence (via `-S`, which is portable and
    /// returns 1 for an absent chain on both legacy and nft-backed iptables)
    /// BEFORE probing the OUTPUT jump. Otherwise the `-C OUTPUT ... -j
    /// FERRUM_UDP_FAIL_CLOSED_A` probe references a missing user chain, whose exit
    /// status is non-portable (1 on legacy, 2 on nft-backed / Ubuntu 24.04
    /// runners), and the strict `status -ne 1` handler misreads status 2 as a
    /// genuine xtables error and aborts the first install forever.
    #[test]
    fn udp_fail_closed_script_probes_chain_existence_before_jump() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.udp_capture_enabled = true;

        let script = IptablesPlan::udp_fail_closed_script(&config);

        let existence_probe = format!("-S {UDP_FAIL_CLOSED_CHAIN_A} >/dev/null 2>&1");
        let existence_idx = script
            .find(&existence_probe)
            .expect("chain existence is probed before the jump");
        let jump_probe = format!("-C OUTPUT -p udp -j {UDP_FAIL_CLOSED_CHAIN_A} 2>/dev/null");
        let jump_idx = script
            .find(&jump_probe)
            .expect("active-guard jump is still probed");
        assert!(
            existence_idx < jump_idx,
            "chain existence must be established before the jump probe:\n{script}"
        );
    }

    /// The chain-absence branch (fresh netns) must take the install/replace-B path
    /// -- it can never fall through to the active-guard swap, which would try to
    /// release a jump to a chain that does not exist yet.
    #[test]
    fn udp_fail_closed_script_absent_chain_installs_guard() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.udp_capture_enabled = true;

        let script = IptablesPlan::udp_fail_closed_script(&config);

        // The outer existence guard's else-branch (chain A absent) installs chain
        // A and activates its OUTPUT jump. Anchor on the existence-probe handler's
        // unique message: everything after it is the install/replace-B path taken
        // when chain A does not exist. (Splitting on `\nelse\n` alone is
        // ambiguous — the strict jump-release loops each contain their own
        // `else`.)
        let existence_handler = format!(
            "could not inspect UDP fail-closed guard chain {UDP_FAIL_CLOSED_CHAIN_A} (status $status)"
        );
        let absent_branch = script
            .split_once(existence_handler.as_str())
            .map(|(_, tail)| tail)
            .expect("existence guard has an absent-chain branch");
        let build_a = absent_branch
            .find(&format!("-N {UDP_FAIL_CLOSED_CHAIN_A}"))
            .expect("absent-chain branch (re)builds guard A");
        let activate_a = absent_branch
            .find(&format!("-I OUTPUT 1 -p udp -j {UDP_FAIL_CLOSED_CHAIN_A}"))
            .expect("absent-chain branch activates guard A");
        assert!(
            build_a < activate_a,
            "absent-chain branch builds guard A before activating its jump:\n{script}"
        );
    }

    /// Model nft-backed iptables, where `-C OUTPUT ... -j <missing-chain>`
    /// returns status 2. A fresh netns must install and activate guard A without
    /// ever issuing that non-portable jump probe for absent guard B.
    #[cfg(target_family = "unix")]
    #[test]
    fn udp_fail_closed_script_executes_first_install_with_nft_missing_chain_status() {
        use std::process::Command;

        let mut config = CaptureConfig::explicit(15006, 15001);
        config.udp_capture_enabled = true;
        config.ip6tables_mode = Ip6TablesMode::Disabled;
        let script = IptablesPlan::udp_fail_closed_script(&config);
        let harness = format!(
            r#"
a_exists=0
b_exists=0
a_active=0
b_active=0
iptables() {{
  case "$*" in
    *"-S {UDP_FAIL_CLOSED_CHAIN_A}"*) [ "$a_exists" -eq 1 ] ;;
    *"-S {UDP_FAIL_CLOSED_CHAIN_B}"*) [ "$b_exists" -eq 1 ] ;;
    *"-C OUTPUT -p udp -j {UDP_FAIL_CLOSED_CHAIN_A}"*)
      [ "$a_exists" -eq 1 ] || return 2
      [ "$a_active" -eq 1 ]
      ;;
    *"-C OUTPUT -p udp -j {UDP_FAIL_CLOSED_CHAIN_B}"*)
      [ "$b_exists" -eq 1 ] || return 2
      [ "$b_active" -eq 1 ]
      ;;
    *"-N {UDP_FAIL_CLOSED_CHAIN_A}"*) a_exists=1 ;;
    *"-N {UDP_FAIL_CLOSED_CHAIN_B}"*) b_exists=1 ;;
    *"-I OUTPUT 1 -p udp -j {UDP_FAIL_CLOSED_CHAIN_A}"*) a_active=1 ;;
    *"-I OUTPUT 1 -p udp -j {UDP_FAIL_CLOSED_CHAIN_B}"*) b_active=1 ;;
    *"-D OUTPUT -p udp -j {UDP_FAIL_CLOSED_CHAIN_A}"*) a_active=0 ;;
    *"-D OUTPUT -p udp -j {UDP_FAIL_CLOSED_CHAIN_B}"*) b_active=0 ;;
    *) return 0 ;;
  esac
}}
{script}
[ "$a_exists" -eq 1 ] && [ "$a_active" -eq 1 ] && [ "$b_active" -eq 0 ]
"#
        );

        let output = Command::new("sh")
            .arg("-c")
            .arg(harness)
            .output()
            .expect("execute generated fail-closed script with nft-modeling shim");
        assert!(
            output.status.success(),
            "fresh-netns first install must succeed when missing-chain jump probes return status 2: status={:?}\nstdout={}\nstderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Fail-closed must be preserved for genuine xtables resource errors on BOTH
    /// the existence probe and the jump probe: any non-1 status aborts the install
    /// with the binary's own exit code (so `set -e` propagates it and the producer
    /// retains the fail-closed cleanup owner) rather than being misread as
    /// chain/jump absence.
    #[test]
    fn udp_fail_closed_script_aborts_on_genuine_resource_error() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.udp_capture_enabled = true;

        let script = IptablesPlan::udp_fail_closed_script(&config);

        // The outer existence and active-jump probes plus each strict release
        // chain-existence probe preserve the same status contract: status 1
        // alone means absent, while every other non-zero status aborts.
        assert_eq!(
            script.matches("if [ \"$status\" -ne 1 ]; then").count(),
            6,
            "all chain-existence probes must fail closed on non-1 status:\n{script}"
        );
        assert!(
            script.contains("could not inspect UDP fail-closed guard chain"),
            "chain-existence probe reports and re-raises a genuine resource error:\n{script}"
        );
        assert!(
            script.contains("could not inspect active UDP fail-closed guard"),
            "jump probe still reports and re-raises a genuine resource error:\n{script}"
        );
        // The two outer handlers and both error paths in each of the four
        // expanded strict-release blocks re-raise the binary's status, so
        // `set -e` aborts and the producer keeps the fail-closed cleanup owner.
        assert_eq!(
            script.matches("exit \"$status\"").count(),
            10,
            "every strict probe re-raises the xtables status to fail closed:\n{script}"
        );
    }

    #[test]
    fn udp_fail_closed_script_preserves_include_scope_and_local_traffic() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.udp_capture_enabled = true;
        config.include_outbound_ports = vec![443];

        let script = IptablesPlan::udp_fail_closed_script(&config);

        assert!(script.contains("-p udp --dport 443 -m addrtype ! --dst-type LOCAL -j DROP"));
        assert!(
            !script.contains("-p udp -d 0.0.0.0/0 -m addrtype ! --dst-type LOCAL -j DROP"),
            "a port-scoped capture policy must not become a catch-all guard: {script}"
        );
        assert!(
            script
                .lines()
                .filter(|line| line.contains("-j DROP"))
                .all(|line| line.contains("! --dst-type LOCAL")),
            "pod-local/loopback UDP is outside the outbound capture contract: {script}"
        );
    }

    #[test]
    fn iptables_setup_script_fails_closed_with_set_e() {
        // The injector runs this script as the init container's `/bin/sh -c`
        // body. Without `set -e` a rule that fails mid-script would still exit 0,
        // starting the pod with a partial ruleset that lets egress bypass mesh
        // capture (and mesh_authz). It must fail closed.
        let plan = IptablesPlan::for_config(&CaptureConfig::explicit(15006, 15001)).unwrap();
        let script = plan.script();
        assert!(
            script.starts_with("set -e\n"),
            "setup script must start with `set -e` to fail closed on a partial ruleset, got:\n{script}"
        );
        // The idempotent guards must survive `set -e`: `-N ... || true` and
        // `-C ... || -A ...` must not abort on the expected chain-exists /
        // rule-absent misses.
        assert!(
            script.contains("|| true"),
            "chain creation must stay idempotent under set -e"
        );
        assert!(
            script.contains(" -C ") && script.contains("|| iptables"),
            "append must stay check-then-add idempotent under set -e"
        );
    }

    #[test]
    fn explicit_capture_defaults_to_proxy_uid_exclusion() {
        let config = CaptureConfig::explicit(15006, 15001);

        assert_eq!(config.proxy_uid, Some(DEFAULT_PROXY_UID));
        assert!(
            IptablesPlan::for_config(&config)
                .unwrap()
                .v4_commands
                .iter()
                .any(|cmd| cmd.contains("--uid-owner 1337"))
        );
    }

    #[test]
    fn ebpf_falls_back_on_old_kernel() {
        assert!(should_fallback_to_iptables("5.4.0"));
        assert!(!should_fallback_to_iptables("5.7.0"));
        assert!(!should_fallback_to_iptables("6.6.12"));
    }

    #[test]
    fn ebpf_plan_carries_iptables_fallback() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Ebpf;

        let plan = EbpfPlan::for_config(&config).unwrap();

        assert!(plan.enabled);
        assert_eq!(plan.required_kernel, "5.7");
        assert_eq!(plan.fallback.ip6tables_mode, Ip6TablesMode::Auto);
        assert!(
            plan.fallback
                .v4_commands
                .iter()
                .any(|cmd| cmd.contains("--uid-owner 1337"))
        );
        assert!(
            plan.fallback
                .v4_commands
                .iter()
                .any(|cmd| cmd.contains("--to-ports 15001"))
        );
    }

    #[test]
    fn ebpf_fallback_script_contains_kernel_check_and_iptables() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Ebpf;

        let plan = EbpfPlan::for_config(&config).unwrap();
        let script = plan.fallback_script();

        assert!(script.contains("uname -r"));
        assert!(script.contains("-lt 5"));
        assert!(script.contains("-lt 7"));
        assert!(script.contains("falling back to iptables"));
        assert!(script.contains("supports eBPF"));
        assert!(script.contains("--to-ports 15001"));
        assert!(script.contains("--to-ports 15006"));
    }

    #[test]
    fn ebpf_fallback_script_preserves_required_ip6tables_mode() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Ebpf;
        config.ip6tables_mode = Ip6TablesMode::Required;
        config.include_cidrs = vec!["fd00::/8".to_string()];

        let plan = EbpfPlan::for_config(&config).unwrap();
        let script = plan.fallback_script();

        assert_eq!(plan.fallback.ip6tables_mode, Ip6TablesMode::Required);
        assert!(script.contains("ip6tables is required for IPv6 mesh capture"));
        assert!(script.contains("ip6tables nat table is required for IPv6 mesh capture"));
    }

    #[test]
    fn cidr_validation_checks_prefix_range() {
        assert!(validate_cidr_list(&["10.0.0.0/8".to_string()]).is_ok());
        assert!(validate_cidr_list(&["10.0.0.0/64".to_string()]).is_err());
    }

    #[test]
    fn cleanup_commands_reverses_setup() {
        let cleanup = IptablesPlan::cleanup_commands(true);

        // Must remove jumps from built-in chains first
        assert!(cleanup.iter().any(|cmd| cmd.contains("-D OUTPUT")));
        assert!(cleanup.iter().any(|cmd| cmd.contains("-D PREROUTING")));

        // Must flush then delete custom chains
        assert!(
            cleanup
                .iter()
                .any(|cmd| cmd.contains("-F FERRUM_MESH_INBOUND"))
        );
        assert!(
            cleanup
                .iter()
                .any(|cmd| cmd.contains("-F FERRUM_MESH_OUTBOUND"))
        );
        assert!(
            cleanup
                .iter()
                .any(|cmd| cmd.contains("-X FERRUM_MESH_INBOUND"))
        );
        assert!(
            cleanup
                .iter()
                .any(|cmd| cmd.contains("-X FERRUM_MESH_OUTBOUND"))
        );

        // Flush must come before delete (chain must be empty before removal)
        let flush_inbound_pos = cleanup
            .iter()
            .position(|cmd| cmd.contains("-F FERRUM_MESH_INBOUND"))
            .unwrap();
        let delete_inbound_pos = cleanup
            .iter()
            .position(|cmd| cmd.contains("-X FERRUM_MESH_INBOUND"))
            .unwrap();
        assert!(
            flush_inbound_pos < delete_inbound_pos,
            "flush must precede delete for FERRUM_MESH_INBOUND"
        );

        let flush_outbound_pos = cleanup
            .iter()
            .position(|cmd| cmd.contains("-F FERRUM_MESH_OUTBOUND"))
            .unwrap();
        let delete_outbound_pos = cleanup
            .iter()
            .position(|cmd| cmd.contains("-X FERRUM_MESH_OUTBOUND"))
            .unwrap();
        assert!(
            flush_outbound_pos < delete_outbound_pos,
            "flush must precede delete for FERRUM_MESH_OUTBOUND"
        );

        // Jump deletions must come before flush (no new traffic enters chains
        // while they are being torn down)
        let delete_output_pos = cleanup
            .iter()
            .position(|cmd| cmd.contains("-D OUTPUT"))
            .unwrap();
        assert!(
            delete_output_pos < flush_outbound_pos,
            "OUTPUT jump delete must precede OUTBOUND flush"
        );
        let delete_prerouting_pos = cleanup
            .iter()
            .position(|cmd| cmd.contains("-D PREROUTING"))
            .unwrap();
        assert!(
            delete_prerouting_pos < flush_inbound_pos,
            "PREROUTING jump delete must precede INBOUND flush"
        );
    }

    #[test]
    fn cleanup_commands_all_tolerate_missing_chains() {
        let cleanup = IptablesPlan::cleanup_commands(true);

        // Ordinary cleanup remains best-effort. Fail-closed guard cleanup uses a
        // strict loop instead: status 1 (missing jump) is still a no-op, while
        // resource errors propagate so cleanup cannot report success with a DROP
        // jump left active.
        for cmd in &cleanup {
            assert!(
                tolerates_missing_cleanup_state(cmd),
                "cleanup command must tolerate missing chains: {cmd}"
            );
        }
    }

    #[test]
    fn iptables_plan_waits_for_xtables_lock() {
        let plan = IptablesPlan::for_config(&CaptureConfig::explicit(15006, 15001)).unwrap();

        for cmd in plan.v4_commands {
            assert!(
                cmd.contains(" -w 5 "),
                "iptables command should wait briefly for xtables lock: {cmd}"
            );
        }
    }

    #[test]
    fn setup_then_cleanup_covers_all_chains() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.proxy_uid = Some(DEFAULT_PROXY_UID);

        let setup = IptablesPlan::for_config(&config).unwrap();
        let cleanup = IptablesPlan::cleanup_commands(true);

        // Every custom chain created in setup must be deleted in cleanup
        let setup_chains: Vec<&str> = setup
            .v4_commands
            .iter()
            .filter(|cmd| cmd.contains("-N "))
            .filter_map(|cmd| cmd.split("-N ").nth(1))
            .filter_map(|s| s.split_whitespace().next())
            .collect();

        for chain in &setup_chains {
            assert!(
                cleanup
                    .iter()
                    .any(|cmd| cmd.contains(&format!("-X {chain}"))),
                "chain {chain} created in setup but not deleted in cleanup"
            );
            assert!(
                cleanup
                    .iter()
                    .any(|cmd| cmd.contains(&format!("-F {chain}"))),
                "chain {chain} created in setup but not flushed in cleanup"
            );
        }

        // Every built-in chain jump in setup must have a corresponding delete in cleanup
        let setup_jumps: Vec<(&str, &str)> = setup
            .v4_commands
            .iter()
            .filter(|cmd| {
                (cmd.contains("-A PREROUTING") || cmd.contains("-C PREROUTING"))
                    || (cmd.contains("-A OUTPUT") || cmd.contains("-C OUTPUT"))
            })
            .filter_map(|cmd| {
                if cmd.contains("PREROUTING") {
                    Some(("PREROUTING", "FERRUM_MESH_INBOUND"))
                } else if cmd.contains("OUTPUT") {
                    Some(("OUTPUT", "FERRUM_MESH_OUTBOUND"))
                } else {
                    None
                }
            })
            .collect();

        for (chain, target) in &setup_jumps {
            assert!(
                cleanup
                    .iter()
                    .any(|cmd| cmd.contains(&format!("-D {chain}"))
                        && cmd.contains(&format!("-j {target}"))),
                "jump from {chain} to {target} in setup but no -D in cleanup"
            );
        }
    }

    #[test]
    fn parse_cidr_env_splits_and_trims() {
        let result = parse_cidr_env("10.0.0.0/8, 172.16.0.0/12 , 192.168.0.0/16");
        assert_eq!(
            result,
            vec![
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
            ]
        );
    }

    #[test]
    fn parse_cidr_env_empty_string_returns_empty() {
        assert!(parse_cidr_env("").is_empty());
    }

    #[test]
    fn parse_port_list_valid() {
        let result = parse_port_list("15001, 15006, 15008 ,15020").unwrap();
        assert_eq!(result, vec![15001, 15006, 15008, 15020]);
    }

    #[test]
    fn parse_port_list_rejects_non_numeric() {
        assert!(parse_port_list("15001,abc").is_err());
    }

    #[test]
    fn parse_port_list_empty_string_returns_empty() {
        assert!(parse_port_list("").unwrap().is_empty());
    }

    #[test]
    fn parse_port_list_rejects_port_zero() {
        let err = parse_port_list("15001,0,15006").unwrap_err();
        assert!(err.contains("port must be 1-65535"), "actual: {err}");
    }

    #[test]
    fn parse_proxy_uid_rejects_invalid_env_value() {
        assert!(parse_proxy_uid("not-a-uid").is_err());
    }

    #[test]
    fn parse_proxy_uid_trims_valid_value() {
        assert_eq!(parse_proxy_uid(" 1338 ").unwrap(), 1338);
    }

    #[test]
    fn parse_proxy_uid_empty_uses_default() {
        assert_eq!(parse_proxy_uid("").unwrap(), DEFAULT_PROXY_UID);
    }

    #[test]
    fn capture_parser_errors_withhold_unregistered_quoted_values() {
        // Leading apostrophes escape the old single-quoted interpolation;
        // embedded double quotes, backslashes and newlines exercise Debug escaping.
        for value in [
            "'capture-secret-5589",
            "prefix'capture-secret-5589'visible-tail",
            "\"capture-secret-5589`visible-tail`",
            "prefix\\\"capture-secret-5589\nvisible-tail",
        ] {
            for (error, expected) in [
                (
                    parse_bool_env(Some(value), "FERRUM_MESH_CAPTURE_UDP_ENABLED").unwrap_err(),
                    "Invalid FERRUM_MESH_CAPTURE_UDP_ENABLED <redacted scalar>. Expected true, false, 1, or 0",
                ),
                (
                    parse_single_port(value, "FERRUM_MESH_CAPTURE_UDP_PORT").unwrap_err(),
                    "Invalid FERRUM_MESH_CAPTURE_UDP_PORT <redacted scalar>. Expected a port in 1-65535",
                ),
                (
                    parse_tproxy_mark(value).unwrap_err(),
                    "Invalid FERRUM_MESH_TPROXY_MARK <redacted scalar>. Expected a 32-bit hex (0x...) or decimal value",
                ),
                (
                    parse_proxy_uid(value).unwrap_err(),
                    "Invalid FERRUM_MESH_PROXY_UID <redacted scalar>. Expected unsigned integer",
                ),
                (
                    CaptureMode::parse(value).unwrap_err(),
                    "Invalid FERRUM_MESH_CAPTURE_MODE <redacted scalar>. Expected: explicit, iptables, or ebpf",
                ),
                (
                    Ip6TablesMode::parse(value).unwrap_err(),
                    "Invalid FERRUM_MESH_IP6TABLES_ENABLED <redacted scalar>. Expected: auto, true, or false",
                ),
                (
                    parse_port_list(&format!("80,{value}")).unwrap_err(),
                    "Invalid port <redacted scalar> in capture exclude ports",
                ),
                (
                    parse_include_port_list(Some(value)).unwrap_err(),
                    "port <redacted scalar>: invalid digit found in string",
                ),
            ] {
                assert_eq!(crate::startup::sanitize_startup_cause(error, &[]), expected);
            }
        }
    }

    #[test]
    fn capture_bool_and_mode_parsing_decisions_are_unchanged() {
        let var = "FERRUM_MESH_CAPTURE_IPV6_ENABLED";
        for (raw, expected) in [
            (None, false),
            (Some(""), false),
            (Some(" \t "), false),
            (Some(" true "), true),
            (Some("TRUE"), true),
            (Some("1"), true),
            (Some(" false "), false),
            (Some("FALSE"), false),
            (Some("0"), false),
        ] {
            assert_eq!(parse_bool_env(raw, var).unwrap(), expected);
        }
        for raw in ["2", "-1", "01", "yes", "auto"] {
            let error = parse_bool_env(Some(raw), var).unwrap_err();
            assert_eq!(
                crate::startup::sanitize_startup_cause(error, &[]),
                "Invalid FERRUM_MESH_CAPTURE_IPV6_ENABLED <redacted scalar>. Expected true, false, 1, or 0"
            );
        }
        for (raw, expected) in [
            ("AUTO", Ip6TablesMode::Auto),
            ("true", Ip6TablesMode::Required),
            ("REQUIRED", Ip6TablesMode::Required),
            ("false", Ip6TablesMode::Disabled),
            ("DISABLED", Ip6TablesMode::Disabled),
        ] {
            assert_eq!(Ip6TablesMode::parse(raw).unwrap(), expected);
        }
        for raw in ["", " auto ", "1", "0"] {
            assert!(Ip6TablesMode::parse(raw).is_err());
        }
        for (raw, expected) in [
            ("EXPLICIT", CaptureMode::Explicit),
            ("IPTABLES", CaptureMode::Iptables),
            ("EBPF", CaptureMode::Ebpf),
        ] {
            assert_eq!(CaptureMode::parse(raw).unwrap(), expected);
        }
        assert!(CaptureMode::parse(" explicit ").is_err());
    }

    #[test]
    fn capture_numeric_boundaries_preserve_decisions_and_rendered_reasons() {
        let var = "FERRUM_MESH_CAPTURE_UDP_PORT";
        for (raw, expected) in [("1", 1), (" 65535 ", u16::MAX), ("+1", 1)] {
            assert_eq!(parse_single_port(raw, var).unwrap(), expected);
            assert_eq!(parse_port_list(raw).unwrap(), vec![expected]);
            assert_eq!(
                parse_include_port_list(Some(raw)).unwrap(),
                ParsedIncludePorts::Ports(vec![expected])
            );
        }
        for raw in ["0", " 000 ", "+0"] {
            for (error, expected) in [
                (
                    parse_single_port(raw, var).unwrap_err(),
                    "Invalid FERRUM_MESH_CAPTURE_UDP_PORT <redacted scalar>: port must be 1-65535",
                ),
                (
                    parse_port_list(raw).unwrap_err(),
                    "Invalid port <redacted scalar> in capture exclude ports: port must be 1-65535",
                ),
                (
                    parse_include_port_list(Some(raw)).unwrap_err(),
                    "port <redacted scalar>: port must be 1-65535",
                ),
            ] {
                assert_eq!(crate::startup::sanitize_startup_cause(error, &[]), expected);
            }
        }
        for raw in ["", "-1", "65536", "4294967296"] {
            let error = parse_single_port(raw, var).unwrap_err();
            assert_eq!(
                crate::startup::sanitize_startup_cause(error, &[]),
                "Invalid FERRUM_MESH_CAPTURE_UDP_PORT <redacted scalar>. Expected a port in 1-65535"
            );
        }
        for (raw, expected) in [("1", 1), (" 4294967295 ", u32::MAX), ("+1", 1)] {
            assert_eq!(parse_tproxy_mark(raw).unwrap(), expected);
            assert_eq!(parse_proxy_uid(raw).unwrap(), expected);
        }
        for (raw, expected) in [("0x1", 1), (" 0XFFFFFFFF ", u32::MAX)] {
            assert_eq!(parse_tproxy_mark(raw).unwrap(), expected);
        }
        for raw in ["0", " 000 ", "+0"] {
            assert_eq!(
                crate::startup::sanitize_startup_cause(parse_proxy_uid(raw).unwrap_err(), &[]),
                "Invalid FERRUM_MESH_PROXY_UID: proxy UID must be non-zero to avoid bypassing capture for all root processes"
            );
        }
        assert_eq!(parse_proxy_uid(" \t ").unwrap(), DEFAULT_PROXY_UID);
        for raw in ["0", " 000 ", "0x0", "0X00"] {
            let error = parse_tproxy_mark(raw).unwrap_err();
            assert_eq!(
                crate::startup::sanitize_startup_cause(error, &[]),
                "Invalid FERRUM_MESH_TPROXY_MARK <redacted scalar>: mark must be non-zero"
            );
        }
        for raw in ["-1", "4294967296", "0x100000000"] {
            assert_eq!(
                crate::startup::sanitize_startup_cause(parse_tproxy_mark(raw).unwrap_err(), &[]),
                "Invalid FERRUM_MESH_TPROXY_MARK <redacted scalar>. Expected a 32-bit hex (0x...) or decimal value"
            );
            assert_eq!(
                crate::startup::sanitize_startup_cause(parse_proxy_uid(raw).unwrap_err(), &[]),
                "Invalid FERRUM_MESH_PROXY_UID <redacted scalar>. Expected unsigned integer"
            );
        }
    }

    #[test]
    fn capture_cidr_errors_withhold_values_and_keep_family_bounds() {
        for (cidr, expected) in [
            (
                "'capture-secret`5589`\"\nvisible-tail",
                "CIDR <redacted scalar> must include a prefix length",
            ),
            (
                "'capture-secret`5589`\"\nvisible-tail/8",
                "CIDR <redacted scalar> has invalid IP address",
            ),
            (
                "fd00::/'capture-secret`5589`\"\nvisible-tail",
                "CIDR <redacted scalar> has invalid prefix length",
            ),
            (
                "10.0.0.0/33",
                "CIDR <redacted scalar> prefix length <redacted scalar> exceeds max 32",
            ),
            (
                "fd00::/129",
                "CIDR <redacted scalar> prefix length <redacted scalar> exceeds max 128",
            ),
            (
                "fd00::/256",
                "CIDR <redacted scalar> has invalid prefix length",
            ),
        ] {
            let error = validate_cidr_list(&[cidr.to_string()]).unwrap_err();
            assert_eq!(crate::startup::sanitize_startup_cause(error, &[]), expected);
        }
        for cidr in ["0.0.0.0/0", "10.0.0.1/32", "::/0", "fd00::1/128"] {
            assert!(validate_cidr_list(&[cidr.to_string()]).is_ok());
        }
    }

    #[test]
    fn capture_annotation_errors_keep_schema_keys_and_fixed_examples() {
        let istio = ISTIO_INCLUDE_OUTBOUND_PORTS_ANNOTATION;
        let ferrum = FERRUM_INCLUDE_OUTBOUND_PORTS_ANNOTATION;
        let value = "'capture-secret`5589`\"\nvisible-tail";
        let error = include_outbound_ports_from_annotations([(ferrum, Some(value))]).unwrap_err();
        assert_eq!(
            crate::startup::sanitize_startup_cause(error, &[]),
            "invalid `ferrum.io/includeOutboundPorts`: port <redacted scalar>: invalid digit found in string"
        );
        // Arbitrary keys accepted by the public helper are values, not schema.
        let error = include_outbound_ports_from_annotations([(value, Some(value))]).unwrap_err();
        assert_eq!(
            crate::startup::sanitize_startup_cause(error, &[]),
            "invalid <redacted scalar>: port <redacted scalar>: invalid digit found in string"
        );
        for key in [istio, value] {
            for (first, second, reason) in [
                (
                    "80",
                    "*",
                    "wildcard `*` cannot be combined with explicit includeOutboundPorts",
                ),
                (
                    "*",
                    "80",
                    "explicit includeOutboundPorts cannot be combined with wildcard `*`",
                ),
            ] {
                let error = include_outbound_ports_from_annotations([
                    (key, Some(first)),
                    (ferrum, Some(second)),
                ])
                .unwrap_err();
                let key_label = if key == istio {
                    "`traffic.sidecar.istio.io/includeOutboundPorts`"
                } else {
                    "<redacted scalar>"
                };
                assert_eq!(
                    crate::startup::sanitize_startup_cause(error, &[]),
                    format!("invalid `ferrum.io/includeOutboundPorts`: {reason} in {key_label}")
                );
            }
        }
        for raw in ["*,80", "80,*", "*,*"] {
            let error = parse_include_port_list(Some(raw)).unwrap_err();
            assert_eq!(
                crate::startup::sanitize_startup_cause(error, &[]),
                "wildcard `*` must be the only includeOutboundPorts token"
            );
        }
        for (name, expected) in [
            ("..", "host capture interface name must not be `.` or `..`"),
            (
                "-veth",
                "host capture interface name must not start with `-`",
            ),
            (
                "veth+",
                "host capture interface name must contain only ASCII letters, digits, `.`, `_`, or `-` (a `+` suffix would be an iptables prefix wildcard)",
            ),
        ] {
            let error = validate_host_capture_interface(name).unwrap_err();
            assert_eq!(crate::startup::sanitize_startup_cause(error, &[]), expected);
        }
    }

    #[test]
    fn iptables_plan_emits_inbound_exclude_return_rules_before_redirect() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.exclude_inbound_ports = vec![15090, 22];

        let plan = IptablesPlan::for_config(&config).unwrap();

        for port in [15090, 22] {
            assert!(
                plan.v4_commands
                    .iter()
                    .any(|cmd| cmd.contains("FERRUM_MESH_INBOUND")
                        && cmd.contains(&format!("--dport {port} -j RETURN"))),
                "inbound RETURN rule missing for port {port}"
            );
        }

        // CRITICAL: every RETURN rule must precede the inbound REDIRECT,
        // otherwise the catch-all REDIRECT fires first and the exclusion is
        // silently bypassed.
        let redirect_pos = plan
            .v4_commands
            .iter()
            .position(|cmd| {
                cmd.contains("FERRUM_MESH_INBOUND")
                    && cmd.contains(&format!("REDIRECT --to-ports {}", config.inbound_port))
            })
            .expect("inbound REDIRECT command");
        for port in [15090, 22] {
            let return_pos = plan
                .v4_commands
                .iter()
                .position(|cmd| {
                    cmd.contains("FERRUM_MESH_INBOUND")
                        && cmd.contains(&format!("--dport {port} -j RETURN"))
                })
                .expect("inbound RETURN command");
            assert!(
                return_pos < redirect_pos,
                "inbound RETURN for port {port} must precede the REDIRECT"
            );
        }
    }

    #[test]
    fn iptables_plan_omits_inbound_returns_when_empty() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;

        let plan = IptablesPlan::for_config(&config).unwrap();

        assert!(
            !plan
                .v4_commands
                .iter()
                .any(|cmd| cmd.contains("FERRUM_MESH_INBOUND") && cmd.contains("-j RETURN")),
            "no inbound RETURN rules expected when exclude_inbound_ports is empty"
        );
    }

    #[test]
    fn iptables_plan_keeps_cidr_redirect_when_include_ports_empty() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["10.0.0.0/8".to_string()];

        let plan = IptablesPlan::for_config(&config).unwrap();

        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("-p tcp -d 10.0.0.0/8 -j REDIRECT --to-ports 15001")),
            "CIDR-only include rule should remain when includeOutboundPorts is unset"
        );
    }

    #[test]
    fn iptables_plan_emits_per_port_redirects_when_include_ports_set() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_outbound_ports = vec![5432, 9092];

        let plan = IptablesPlan::for_config(&config).unwrap();

        for port in [5432, 9092] {
            assert!(
                plan.v4_commands.iter().any(|cmd| cmd.contains(&format!(
                    "-p tcp --dport {port} -j REDIRECT --to-ports 15001"
                ))),
                "includeOutboundPorts REDIRECT missing for port {port}: {:?}",
                plan.v4_commands
            );
        }
        assert!(
            !plan
                .v4_commands
                .iter()
                .any(|cmd| cmd.contains("-p tcp -d 0.0.0.0/0 -j REDIRECT")),
            "implicit catch-all CIDR must not capture all ports before port rules"
        );
    }

    #[test]
    fn iptables_plan_adds_include_ports_to_include_cidrs() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["10.0.0.0/8".to_string()];
        config.include_cidrs_explicit = true;
        config.include_outbound_ports = vec![5432];

        let plan = IptablesPlan::for_config(&config).unwrap();

        let scoped_port_rule = plan
            .v4_commands
            .iter()
            .position(|cmd| cmd.contains("-p tcp --dport 5432 -j REDIRECT --to-ports 15001"))
            .expect("includeOutboundPorts should redirect port 5432 independently");
        assert!(
            scoped_port_rule > 0,
            "port include rule should be emitted after chain setup: {:?}",
            plan.v4_commands
        );
        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("-p tcp -d 10.0.0.0/8 -j REDIRECT")),
            "includeOutboundPorts should not suppress CIDR-only redirects"
        );
        assert!(
            !plan
                .v4_commands
                .iter()
                .any(|cmd| cmd.contains("-p tcp -d 10.0.0.0/8 --dport 5432 -j REDIRECT")),
            "includeOutboundPorts must be additive, not intersected with include CIDRs"
        );
    }

    #[test]
    fn iptables_plan_wildcard_include_ports_redirects_all_destinations() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["10.0.0.0/8".to_string()];
        config.include_cidrs_explicit = true;
        config.include_all_outbound_ports = true;

        let plan = IptablesPlan::for_config(&config).unwrap();

        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("-p tcp -j REDIRECT --to-ports 15001")),
            "wildcard includeOutboundPorts must redirect all outbound ports regardless of destination IP: {:?}",
            plan.v4_commands
        );
        assert!(
            !plan.v4_commands.iter().any(|cmd| cmd.contains("--dport")),
            "wildcard includeOutboundPorts should not emit port-narrowing rules: {:?}",
            plan.v4_commands
        );
    }

    #[test]
    fn iptables_plan_falls_back_to_catch_all_when_ipv4_include_set_filters_empty() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["fd00::/8".to_string()];
        config.include_cidrs_explicit = true;
        let plan = IptablesPlan::for_config(&config).unwrap();

        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| { cmd.contains("-p tcp -j REDIRECT --to-ports 15001") }),
            "When no IPv4 CIDR include remains for iptables, plan must fail closed with catch-all IPv4 redirect: {:?}",
            plan.v4_commands
        );
        assert!(
            !plan.v4_commands.iter().any(|cmd| cmd.contains("fd00::/8")),
            "IPv6 include CIDR must not appear in the IPv4 iptables plan: {:?}",
            plan.v4_commands
        );
        assert!(
            plan.v6_commands
                .iter()
                .any(|cmd| { cmd.contains("-p tcp -d fd00::/8 -j REDIRECT --to-ports 15001") }),
            "IPv6 include CIDR should be rendered into ip6tables: {:?}",
            plan.v6_commands
        );
    }

    #[test]
    fn iptables_plan_orders_exclude_port_before_overlapping_include_port() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.exclude_ports = vec![5432];
        config.include_outbound_ports = vec![5432];

        let plan = IptablesPlan::for_config(&config).unwrap();
        let exclude_idx = plan
            .v4_commands
            .iter()
            .position(|cmd| cmd.contains("-p tcp --dport 5432 -j RETURN"))
            .expect("exclude port RETURN rule should be emitted");
        let include_idx = plan
            .v4_commands
            .iter()
            .position(|cmd| cmd.contains("--dport 5432 -j REDIRECT --to-ports 15001"))
            .expect("include port REDIRECT rule should be emitted");

        assert!(
            exclude_idx < include_idx,
            "excludeOutboundPorts must win over includeOutboundPorts by rule order: {:?}",
            plan.v4_commands
        );
    }
    #[test]
    fn iptables_plan_partitions_ipv4_and_ipv6_cidrs() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.exclude_cidrs = vec!["10.0.0.0/8".to_string(), "fd00::/8".to_string()];
        config.include_cidrs = vec!["172.16.0.0/12".to_string(), "2001:db8::/32".to_string()];

        let plan = IptablesPlan::for_config(&config).unwrap();

        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("-d 10.0.0.0/8 -j RETURN")),
            "IPv4 exclude CIDR must still appear in the plan"
        );
        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("-d 172.16.0.0/12 -j REDIRECT --to-ports 15001")),
            "IPv4 include CIDR must still appear in the IPv4 plan"
        );
        assert!(
            !plan.v4_commands.iter().any(|cmd| cmd.contains("::/")),
            "IPv6 CIDRs must not appear in IPv4 commands: {:?}",
            plan.v4_commands
        );
        assert!(
            plan.v6_commands
                .iter()
                .all(|cmd| cmd.starts_with("ip6tables ")),
            "IPv6 commands must use ip6tables: {:?}",
            plan.v6_commands
        );
        assert!(
            plan.v6_commands
                .iter()
                .any(|cmd| cmd.contains("-d fd00::/8 -j RETURN")),
            "IPv6 exclude CIDR must appear in the IPv6 plan"
        );
        assert!(
            plan.v6_commands
                .iter()
                .any(|cmd| cmd.contains("-d 2001:db8::/32 -j REDIRECT --to-ports 15001")),
            "IPv6 include CIDR must appear in the IPv6 plan"
        );
    }

    #[test]
    fn iptables_plan_v6_empty_when_ip6tables_disabled() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.ip6tables_mode = Ip6TablesMode::Disabled;
        config.include_cidrs = vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()];

        let plan = IptablesPlan::for_config(&config).unwrap();

        assert!(
            plan.v4_commands
                .iter()
                .any(|cmd| cmd.contains("-d 10.0.0.0/8 -j REDIRECT --to-ports 15001")),
            "IPv4 include CIDR must still appear in the plan"
        );
        assert!(
            plan.v6_commands.is_empty(),
            "disabled ip6tables mode must suppress IPv6 commands"
        );
    }

    #[test]
    fn iptables_plan_routes_ipv6_include_to_v6_commands_only() {
        // Spec change (PR #926 / 4b273b1f): when the include-CIDR list
        // contains only IPv6 entries (so the IPv4 family has no specific
        // CIDR to redirect), the plan must fall back to a catch-all
        // IPv4 outbound REDIRECT rather than silently leaving IPv4 traffic
        // un-captured. Operators who relied on the previous behavior to
        // narrow capture to one address family should either set
        // `include_cidrs_explicit=false` (so the catch-all rules out IPv4
        // entirely) or add an explicit IPv4 CIDR.
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["fd00::/8".to_string()];
        config.include_cidrs_explicit = true;

        let plan = IptablesPlan::for_config(&config).unwrap();

        assert!(
            plan.v4_commands.iter().any(|cmd| {
                cmd.contains("FERRUM_MESH_OUTBOUND")
                    && cmd.contains("-p tcp -j REDIRECT --to-ports 15001")
            }),
            "IPv6-only include set must fall back to a catch-all IPv4 outbound REDIRECT (fail-closed): {:?}",
            plan.v4_commands
        );
        assert!(
            plan.v4_commands.iter().any(|cmd| {
                cmd.contains("FERRUM_MESH_INBOUND") && cmd.contains("REDIRECT --to-ports 15006")
            }),
            "IPv4 inbound REDIRECT must remain active even when the only include CIDR is IPv6"
        );
        assert!(
            plan.v6_commands.iter().any(|cmd| {
                cmd.contains("FERRUM_MESH_OUTBOUND")
                    && cmd.contains("-d fd00::/8 -j REDIRECT --to-ports 15001")
            }),
            "IPv6 outbound REDIRECT should be emitted through ip6tables"
        );
    }

    #[test]
    fn iptables_script_wraps_ipv6_commands_for_auto_probe() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.include_cidrs = vec!["fd00::/8".to_string()];

        let script = IptablesPlan::for_config(&config).unwrap().script();

        assert!(script.contains("command -v ip6tables"));
        assert!(script.contains("ip6tables -t nat -w 5 -L"));
        assert!(script.contains("ip6tables nat table unavailable"));
        assert!(script.contains("skipping IPv6 mesh capture rules"));
        assert!(script.contains("ip6tables -t nat"));
    }

    #[test]
    fn iptables_script_requires_ip6tables_when_configured_true() {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.ip6tables_mode = Ip6TablesMode::Required;
        config.include_cidrs = vec!["fd00::/8".to_string()];

        let plan = IptablesPlan::for_config(&config).unwrap();
        let script = plan.script();

        assert!(script.contains("ip6tables is required for IPv6 mesh capture"));
        assert!(script.contains("ip6tables nat table is required for IPv6 mesh capture"));
        assert!(script.contains("ip6tables -t nat -w 5 -L"));
        assert!(script.contains("exit 1"));
        assert!(script.contains("ip6tables -t nat"));
        assert!(
            script
                .find("ip6tables is required for IPv6 mesh capture")
                .expect("ip6tables preflight")
                < script.find("iptables -t nat").expect("IPv4 setup"),
            "hard-required ip6tables preflight should run before IPv4 setup: {script}"
        );
    }

    #[test]
    fn cleanup_script_does_not_preflight_required_ip6tables() {
        let script = IptablesPlan::cleanup_script(true, Ip6TablesMode::Required, false);

        assert!(script.contains("iptables -t nat"));
        assert!(script.contains("ip6tables -t nat"));
        assert!(
            !script.contains("ip6tables is required for IPv6 mesh capture"),
            "cleanup must remain best-effort and avoid aborting v4 teardown when ip6tables is unavailable: {script}"
        );
        assert!(
            !script.contains("ip6tables -t nat -L"),
            "cleanup must not probe ip6tables nat availability before best-effort teardown: {script}"
        );
    }

    #[test]
    fn cidr_family_classifies_families() {
        assert_eq!(cidr_family("10.0.0.0/8"), Some(CidrFamily::V4));
        assert_eq!(cidr_family("0.0.0.0/0"), Some(CidrFamily::V4));
        assert_eq!(cidr_family("127.0.0.0/8"), Some(CidrFamily::V4));
        assert_eq!(cidr_family("fd00::/8"), Some(CidrFamily::V6));
        assert_eq!(cidr_family("2001:db8::/32"), Some(CidrFamily::V6));
        assert_eq!(cidr_family("::/0"), Some(CidrFamily::V6));
        // Malformed shapes are not IPv4; admission validator catches these earlier.
        assert_eq!(cidr_family("not-a-cidr"), None);
        assert_eq!(cidr_family("10.0.0.0"), None);
    }

    #[test]
    fn ip6tables_mode_parse_accepts_documented_values() {
        assert_eq!(Ip6TablesMode::parse("auto").unwrap(), Ip6TablesMode::Auto);
        assert_eq!(
            Ip6TablesMode::parse("true").unwrap(),
            Ip6TablesMode::Required
        );
        assert_eq!(
            Ip6TablesMode::parse("required").unwrap(),
            Ip6TablesMode::Required
        );
        assert_eq!(
            Ip6TablesMode::parse("false").unwrap(),
            Ip6TablesMode::Disabled
        );
        assert!(Ip6TablesMode::parse("sometimes").is_err());
    }

    // Serialize env-driven tests in this module so parallel cargo test runs do
    // not race on the same `FERRUM_MESH_CAPTURE_*` vars consumed by `from_env`.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_capture_env<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let keys = [
            "FERRUM_MESH_CAPTURE_MODE",
            "FERRUM_MESH_PROXY_UID",
            "FERRUM_MESH_CAPTURE_INCLUDE_CIDRS",
            "FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS",
            "FERRUM_MESH_CAPTURE_EXCLUDE_PORTS",
            "FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS",
            "FERRUM_MESH_IP6TABLES_ENABLED",
            "FERRUM_MESH_CAPTURE_UDP_ENABLED",
            "FERRUM_MESH_CAPTURE_UDP_PORT",
            "FERRUM_MESH_TPROXY_MARK",
        ];
        for key in keys {
            // SAFETY: test-only env mutation, serialized by ENV_LOCK above.
            unsafe { std::env::remove_var(key) };
        }
        for (key, value) in vars {
            // SAFETY: test-only env mutation, serialized by ENV_LOCK above.
            unsafe { std::env::set_var(key, value) };
        }
        f();
        for key in keys {
            // SAFETY: test-only env mutation, serialized by ENV_LOCK above.
            unsafe { std::env::remove_var(key) };
        }
    }

    #[test]
    fn from_env_parses_exclude_inbound_ports() {
        with_capture_env(
            &[("FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS", "15090, 22")],
            || {
                let config = CaptureConfig::from_env().expect("config");
                assert_eq!(config.exclude_inbound_ports, vec![15090, 22]);
            },
        );
    }

    #[test]
    fn from_env_defaults_exclude_inbound_ports_to_empty() {
        with_capture_env(&[], || {
            let config = CaptureConfig::from_env().expect("config");
            assert!(config.exclude_inbound_ports.is_empty());
            assert_eq!(config.ip6tables_mode, Ip6TablesMode::Auto);
        });
    }

    #[test]
    fn from_env_marks_default_exclude_ports_as_implicit() {
        with_capture_env(&[], || {
            let mut config = CaptureConfig::from_env().expect("config");
            assert_eq!(config.exclude_ports, vec![15001, 15006, 15008, 15020]);
            assert!(!config.exclude_ports_explicit);
            config.clear_implicit_exclude_ports();
            assert!(config.exclude_ports.is_empty());
        });
    }

    #[test]
    fn from_env_preserves_explicit_exclude_ports_for_ambient_udp() {
        with_capture_env(&[("FERRUM_MESH_CAPTURE_EXCLUDE_PORTS", "53,123")], || {
            let mut config = CaptureConfig::from_env().expect("config");
            assert_eq!(config.exclude_ports, vec![53, 123]);
            assert!(config.exclude_ports_explicit);
            config.clear_implicit_exclude_ports();
            assert_eq!(config.exclude_ports, vec![53, 123]);
        });
    }

    #[test]
    fn from_env_rejects_invalid_exclude_inbound_ports() {
        with_capture_env(
            &[("FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS", "not-a-port")],
            || {
                let result = CaptureConfig::from_env();
                assert!(result.is_err());
            },
        );
    }

    #[test]
    fn from_env_parses_ip6tables_mode() {
        with_capture_env(&[("FERRUM_MESH_IP6TABLES_ENABLED", "true")], || {
            let config = CaptureConfig::from_env().expect("config");
            assert_eq!(config.ip6tables_mode, Ip6TablesMode::Required);
        });
    }

    #[test]
    fn from_env_rejects_invalid_ip6tables_mode() {
        with_capture_env(&[("FERRUM_MESH_IP6TABLES_ENABLED", "maybe")], || {
            let result = CaptureConfig::from_env();
            assert!(result.is_err());
        });
    }

    // Parser tests for the shared `includeOutboundPorts` surface used by both
    // the injector (iptables init container) and the node-agent eBPF backend.
    // The injector previously owned a private copy of these tests; centralizing
    // them here keeps the two surfaces from drifting.

    #[test]
    fn parse_include_port_list_absent_inputs() {
        assert_eq!(
            parse_include_port_list(None).expect("None"),
            ParsedIncludePorts::Absent
        );
        assert_eq!(
            parse_include_port_list(Some("")).expect("empty"),
            ParsedIncludePorts::Absent
        );
        assert_eq!(
            parse_include_port_list(Some("   ")).expect("blank"),
            ParsedIncludePorts::Absent
        );
        // A list of nothing but separator whitespace is also absent — we
        // never want to inject a phantom wildcard.
        assert_eq!(
            parse_include_port_list(Some(",")).expect("comma-only"),
            ParsedIncludePorts::Ports(Vec::new())
        );
    }

    #[test]
    fn parse_include_port_list_wildcard() {
        assert_eq!(
            parse_include_port_list(Some("*")).expect("wildcard"),
            ParsedIncludePorts::All
        );
        // Surrounding whitespace allowed.
        assert_eq!(
            parse_include_port_list(Some("  *  ")).expect("padded wildcard"),
            ParsedIncludePorts::All
        );
    }

    #[test]
    fn parse_include_port_list_single_port() {
        assert_eq!(
            parse_include_port_list(Some("80")).expect("single port"),
            ParsedIncludePorts::Ports(vec![80])
        );
    }

    #[test]
    fn parse_include_port_list_multiple_ports() {
        assert_eq!(
            parse_include_port_list(Some("80,443,5432")).expect("comma list"),
            ParsedIncludePorts::Ports(vec![80, 443, 5432])
        );
    }

    #[test]
    fn parse_include_port_list_handles_whitespace_and_dups() {
        // Sorted + deduped. Whitespace inside the list is tolerated to match
        // what humans actually type in pod annotations.
        assert_eq!(
            parse_include_port_list(Some("80, 443, 80")).expect("padded list"),
            ParsedIncludePorts::Ports(vec![80, 443])
        );
    }

    #[test]
    fn parse_include_port_list_rejects_mixed_wildcard() {
        let err = parse_include_port_list(Some("*,80")).expect_err("mixed wildcard");
        assert_eq!(
            err,
            "wildcard `*` must be the only includeOutboundPorts token"
        );
        let err = parse_include_port_list(Some("80,*")).expect_err("ports-then-wildcard");
        assert_eq!(
            err,
            "wildcard `*` must be the only includeOutboundPorts token"
        );
    }

    #[test]
    fn parse_include_port_list_rejects_repeated_wildcard() {
        let err = parse_include_port_list(Some("*,*")).expect_err("repeated wildcard");
        assert_eq!(
            err,
            "wildcard `*` must be the only includeOutboundPorts token"
        );
    }

    #[test]
    fn parse_include_port_list_rejects_malformed() {
        assert!(parse_include_port_list(Some("not-a-port")).is_err());
        // Port `0` is reserved; iptables --dport 0 and BPF gate alike would
        // be nonsensical.
        assert!(parse_include_port_list(Some("0")).is_err());
        // Out of range — `u16::MAX + 1`.
        assert!(parse_include_port_list(Some("65536")).is_err());
        assert!(parse_include_port_list(Some("80,bogus")).is_err());
    }

    #[test]
    fn include_outbound_ports_from_annotations_absent() {
        let result = include_outbound_ports_from_annotations([
            ("traffic.sidecar.istio.io/includeOutboundPorts", None),
            ("ferrum.io/includeOutboundPorts", None),
        ])
        .expect("absent annotations");
        assert!(result.is_absent());
        assert_eq!(result, IncludeOutboundPorts::default());
    }

    #[test]
    fn include_outbound_ports_from_annotations_merges_two_aliases() {
        let result = include_outbound_ports_from_annotations([
            (
                "traffic.sidecar.istio.io/includeOutboundPorts",
                Some("80, 443"),
            ),
            ("ferrum.io/includeOutboundPorts", Some("5432, 80")),
        ])
        .expect("merged");
        assert!(!result.all_ports);
        // Sorted + deduped across both annotations.
        assert_eq!(result.ports, vec![80, 443, 5432]);
    }

    #[test]
    fn include_outbound_ports_from_annotations_wildcard_in_either_wins() {
        let result = include_outbound_ports_from_annotations([
            ("traffic.sidecar.istio.io/includeOutboundPorts", Some("*")),
            ("ferrum.io/includeOutboundPorts", None),
        ])
        .expect("wildcard");
        assert!(result.all_ports);
        assert!(result.ports.is_empty());
    }

    #[test]
    fn include_outbound_ports_from_annotations_rejects_mixed_aliases() {
        let err = include_outbound_ports_from_annotations([
            ("traffic.sidecar.istio.io/includeOutboundPorts", Some("80")),
            ("ferrum.io/includeOutboundPorts", Some("*")),
        ])
        .expect_err("mixed wildcard across aliases");
        assert!(err.contains("ferrum.io/includeOutboundPorts"));
        assert!(err.contains("wildcard `*` cannot be combined"));
        assert!(err.contains("traffic.sidecar.istio.io/includeOutboundPorts"));
    }

    #[test]
    fn include_outbound_ports_from_annotations_wildcard_then_explicit_rejected() {
        let err = include_outbound_ports_from_annotations([
            ("traffic.sidecar.istio.io/includeOutboundPorts", Some("*")),
            ("ferrum.io/includeOutboundPorts", Some("80")),
        ])
        .expect_err("explicit-after-wildcard");
        assert!(err.contains("ferrum.io/includeOutboundPorts"));
        assert!(err.contains("explicit includeOutboundPorts cannot be combined with wildcard"));
        assert!(err.contains("traffic.sidecar.istio.io/includeOutboundPorts"));
    }

    #[test]
    fn include_outbound_ports_from_annotations_surfaces_parse_errors() {
        let err = include_outbound_ports_from_annotations([(
            "ferrum.io/includeOutboundPorts",
            Some("80,bogus"),
        )])
        .expect_err("malformed token");
        assert!(err.contains("invalid `ferrum.io/includeOutboundPorts`"));
    }

    // ---- F3 §3.3 Stage 2: UDP TPROXY capture rules (flag-gated, default-off) ----

    fn udp_enabled_iptables_config() -> CaptureConfig {
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        config.udp_capture_enabled = true;
        config
    }

    // ── Ambient per-pod-netns UDP producer builders (#2013) ──────────────────

    #[test]
    fn udp_only_plan_emits_udp_chains_and_no_tcp_nat_chains() {
        // The Ambient per-pod-netns producer installs ONLY the UDP TPROXY chains;
        // Ambient TCP capture rides eBPF/HBONE, so the plan must never touch the
        // `nat` table or emit a TCP REDIRECT.
        let config = udp_enabled_iptables_config();
        let plan = IptablesPlan::udp_only_for_config(&config).unwrap();
        let cmds = &plan.v4_commands;
        assert!(!cmds.is_empty(), "UDP-only plan should emit v4 commands");
        assert!(
            cmds.iter()
                .any(|c| c.contains("-t mangle") && c.contains("-N FERRUM_MESH_UDP_OUTBOUND")),
            "missing UDP outbound mangle chain: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("-t mangle") && c.contains("TPROXY")),
            "missing UDP TPROXY jump: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("ip rule add") && c.contains("fwmark")),
            "missing fwmark policy-routing rule: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("ip route add") && c.contains(&TPROXY_ROUTE_TABLE.to_string())),
            "missing local route into the Ferrum table: {cmds:?}"
        );
        for cmd in cmds {
            assert!(
                !cmd.contains("-t nat"),
                "UDP-only plan must never touch the nat table: {cmd}"
            );
            assert!(
                !cmd.contains("REDIRECT"),
                "UDP-only plan must never emit a TCP REDIRECT: {cmd}"
            );
        }
    }

    #[test]
    fn udp_only_plan_is_outbound_only_unlike_injector() {
        // The Ambient producer installs rules INSIDE every enrolled pod netns
        // (including DESTINATION pods), so it must be OUTBOUND-ONLY: an inbound
        // `--dst-type LOCAL` chain would capture + drop the HBONE relay's delivery
        // to the local app AND the source pod's return-path reply (codex). The
        // injector (Sidecar) still emits the inbound chain. Both flow through the
        // SAME `udp_tproxy_commands_for_family`, so the producer's OUTBOUND rules
        // stay byte-identical to the injector's — only the inbound chain differs.
        let config = udp_enabled_iptables_config();
        let producer = IptablesPlan::udp_only_for_config(&config)
            .unwrap()
            .v4_commands;
        let injector = IptablesPlan::for_config(&config).unwrap().v4_commands;
        assert!(!producer.is_empty());

        // Producer captures egress: OUTBOUND chain + OUTPUT MARK loop + routing.
        assert!(
            producer
                .iter()
                .any(|c| c.contains("-N FERRUM_MESH_UDP_OUTBOUND")),
            "producer must create the outbound UDP chain: {producer:#?}"
        );
        assert!(
            producer
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK")),
            "producer must emit the OUTPUT MARK loop for locally-generated egress"
        );
        assert!(
            producer
                .iter()
                .any(|c| c.contains("ip rule add") && c.contains("fwmark")),
            "producer must install the fwmark policy route"
        );

        // Producer emits NO inbound chain/jump (outbound-only) — this is what keeps
        // the destination relay's delivery + the return-path reply from being
        // captured and dropped in the pod netns.
        for cmd in &producer {
            assert!(
                !cmd.contains("FERRUM_MESH_UDP_INBOUND"),
                "producer must not emit the inbound UDP chain: {cmd}"
            );
        }
        // The injector (Sidecar) DOES still emit the inbound chain — contrast.
        assert!(
            injector
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_INBOUND")),
            "injector should still emit the inbound UDP chain"
        );

        // Every producer (outbound) rule matches an injector rule verbatim: the
        // producer is the injector's UDP rules MINUS the inbound chain, so
        // Ambient-produced and Sidecar-injected pods capture EGRESS identically.
        for cmd in &producer {
            assert!(
                injector.contains(cmd),
                "producer outbound rule must equal an injector rule: {cmd}"
            );
        }
    }

    #[test]
    fn udp_only_plan_host_netns_emits_nothing() {
        // Host-netns UDP suppression survives into the producer path even though
        // the producer never runs in host netns — the invariant is defense in depth.
        let mut config = udp_enabled_iptables_config();
        config.host_netns = true;
        let plan = IptablesPlan::udp_only_for_config(&config).unwrap();
        assert!(
            plan.v4_commands.is_empty() && plan.v6_commands.is_empty(),
            "host-netns UDP-only plan must be empty: {plan:?}"
        );
    }

    #[test]
    fn udp_only_plan_disabled_emits_nothing() {
        let mut config = udp_enabled_iptables_config();
        config.udp_capture_enabled = false;
        let plan = IptablesPlan::udp_only_for_config(&config).unwrap();
        assert!(plan.v4_commands.is_empty() && plan.v6_commands.is_empty());
    }

    #[test]
    fn udp_only_plan_v6_gated_on_configured_v6_cidr() {
        // IPv4-only include → no v6 commands. A ::/0 include → v6 commands emit.
        let v4_only = udp_enabled_iptables_config();
        assert!(
            IptablesPlan::udp_only_for_config(&v4_only)
                .unwrap()
                .v6_commands
                .is_empty(),
            "v4-only config must not emit v6 UDP rules"
        );

        let mut dual = udp_enabled_iptables_config();
        dual.include_cidrs = vec!["0.0.0.0/0".to_string(), "::/0".to_string()];
        dual.include_cidrs_explicit = true;
        let dual_plan = IptablesPlan::udp_only_for_config(&dual).unwrap();
        assert!(
            dual_plan
                .v6_commands
                .iter()
                .any(|c| c.contains("-t mangle") && c.contains("FERRUM_MESH_UDP_OUTBOUND")),
            "::/0 include must emit v6 UDP chains: {:?}",
            dual_plan.v6_commands
        );

        let mut disabled_v6 = dual;
        disabled_v6.ip6tables_mode = Ip6TablesMode::Disabled;
        assert!(
            IptablesPlan::udp_only_for_config(&disabled_v6)
                .unwrap()
                .v6_commands
                .is_empty(),
            "ip6tables disabled must drop v6 UDP rules"
        );
    }

    #[test]
    fn udp_setup_script_is_fail_closed_and_udp_only() {
        let config = udp_enabled_iptables_config();
        let script = IptablesPlan::udp_setup_script(&config).unwrap();
        assert!(
            script.starts_with("set -e"),
            "producer UDP setup must fail closed: {script}"
        );
        assert!(script.contains("FERRUM_MESH_UDP_OUTBOUND"));
        assert!(script.contains("TPROXY"));
        assert!(script.contains("ip rule add") && script.contains("fwmark"));
        assert!(
            script.contains("command -v ip >/dev/null"),
            "must fatally preflight iproute2 before any UDP rule: {script}"
        );
        assert!(
            !script.contains("-t nat") && !script.contains("REDIRECT"),
            "producer setup must not touch TCP nat capture: {script}"
        );
    }

    #[test]
    fn udp_setup_script_empty_when_disabled_or_host_netns() {
        let mut disabled = udp_enabled_iptables_config();
        disabled.udp_capture_enabled = false;
        assert_eq!(IptablesPlan::udp_setup_script(&disabled).unwrap(), "");

        let mut host = udp_enabled_iptables_config();
        host.host_netns = true;
        assert_eq!(
            IptablesPlan::udp_setup_script(&host).unwrap(),
            "",
            "host-netns must emit no UDP setup (no host-netns-safe direction split)"
        );
    }

    #[test]
    fn udp_setup_script_v6_probe_is_mangle_not_nat() {
        // The UDP TPROXY chains live in `mangle`; the producer's v6 availability
        // probe must check `mangle`, not `nat` (codex r10 parity).
        let mut dual = udp_enabled_iptables_config();
        dual.include_cidrs = vec!["0.0.0.0/0".to_string(), "::/0".to_string()];
        dual.include_cidrs_explicit = true;
        let script = IptablesPlan::udp_setup_script(&dual).unwrap();
        assert!(
            script.contains("ip6tables -t mangle"),
            "v6 UDP probe must check the mangle table: {script}"
        );
        assert!(
            !script.contains("ip6tables -t nat"),
            "v6 UDP probe must not check the nat table: {script}"
        );
    }

    #[test]
    fn udp_teardown_script_reaps_udp_state_only() {
        let script = IptablesPlan::udp_teardown_script(true);
        for chain in [
            "FERRUM_MESH_UDP_OUTBOUND",
            "FERRUM_MESH_UDP_INBOUND",
            "FERRUM_MESH_UDP_OUTPUT_MARK",
            "FERRUM_MESH_UDP_REINJECT",
            UDP_FAIL_CLOSED_CHAIN_A,
            UDP_FAIL_CLOSED_CHAIN_B,
        ] {
            assert!(
                script.contains(chain),
                "teardown must reap {chain}: {script}"
            );
        }
        // Exact Ferrum-owned routing teardown (never a table flush / by-lookup rule).
        assert!(
            script.contains(&format!(
                "ip rule del priority {TPROXY_ROUTE_RULE_PRIORITY} lookup {TPROXY_ROUTE_TABLE}"
            )),
            "v4 fwmark rule teardown missing: {script}"
        );
        assert!(
            script.contains(&format!(
                "ip route del local 0.0.0.0/0 dev lo table {TPROXY_ROUTE_TABLE}"
            )),
            "v4 local route teardown missing: {script}"
        );
        // v6 table teardown guarded behind the ip6tables (mangle) probe...
        assert!(script.contains("command -v ip6tables") && script.contains("ip6tables -t mangle"));
        for chain in [UDP_FAIL_CLOSED_CHAIN_A, UDP_FAIL_CLOSED_CHAIN_B] {
            let existence_probe = format!(
                "if iptables -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} -S {chain} >/dev/null 2>&1"
            );
            let jump_release = format!(
                "while true; do\n    if iptables -t mangle -w {XTABLES_LOCK_WAIT_SECONDS} \
                 -C OUTPUT -p udp -j {chain}"
            );
            let existence_idx = script
                .find(&existence_probe)
                .unwrap_or_else(|| panic!("teardown must probe v4 guard chain {chain}: {script}"));
            let release_idx = script.find(&jump_release).unwrap_or_else(|| {
                panic!(
                    "teardown must loop over every duplicate v4 guard jump for {chain}: {script}"
                )
            });
            assert!(
                existence_idx < release_idx,
                "teardown must establish v4 guard-chain existence before probing its jump for {chain}: {script}"
            );
        }
        assert!(
            script
                .find("-D OUTPUT -p udp -j FERRUM_MESH_UDP_OUTPUT_MARK")
                .expect("normal capture OUTPUT cleanup")
                < script
                    .find("-D OUTPUT -p udp -j FERRUM_UDP_FAIL_CLOSED_A")
                    .expect("strict guard cleanup"),
            "normal capture must detach before strict guard cleanup: {script}"
        );
        // ...but v6 routing (`ip -6`) emitted UNCONDITIONALLY (not behind the probe).
        assert!(
            script.contains(&format!(
                "ip -6 rule del priority {TPROXY_ROUTE_RULE_PRIORITY} lookup {TPROXY_ROUTE_TABLE}"
            )),
            "v6 fwmark rule teardown must be unconditional: {script}"
        );
        // No TCP nat teardown.
        assert!(!script.contains("-t nat") && !script.contains("REDIRECT"));
    }

    #[test]
    fn udp_capture_rules_teardown_keeps_guard_until_live_capture_is_ready() {
        let capture_only = IptablesPlan::udp_capture_rules_teardown_script(true);
        assert!(capture_only.contains("FERRUM_MESH_UDP_OUTPUT_MARK"));
        assert!(!capture_only.contains(UDP_FAIL_CLOSED_CHAIN_A));
        assert!(!capture_only.contains(UDP_FAIL_CLOSED_CHAIN_B));

        let guard_only = IptablesPlan::udp_fail_closed_teardown_script();
        assert!(guard_only.starts_with("set -e\n"));
        assert!(guard_only.contains(UDP_FAIL_CLOSED_CHAIN_A));
        assert!(guard_only.contains(UDP_FAIL_CLOSED_CHAIN_B));
        assert!(!guard_only.contains("FERRUM_MESH_UDP_OUTPUT_MARK"));
        assert!(!guard_only.contains("ip rule del"));
        assert!(guard_only.contains("while true; do"));
        assert!(guard_only.contains("-D OUTPUT -p udp -j FERRUM_UDP_FAIL_CLOSED_A"));
        assert!(guard_only.contains("status=$?"));
        assert!(guard_only.contains("exit \"$status\""));
        assert!(guard_only.contains("ip6tables -t mangle"));

        let capture_output = IptablesPlan::udp_capture_output_release_script();
        assert!(capture_output.starts_with("set -e\n"));
        assert!(capture_output.contains("-D OUTPUT -p udp -j FERRUM_MESH_UDP_OUTPUT_MARK"));
        assert!(capture_output.contains("status=$?"));
        assert!(capture_output.contains("ip6tables -t mangle"));
    }

    #[test]
    fn udp_teardown_script_v4_only_still_reaps_stale_v6_guards() {
        let script = IptablesPlan::udp_teardown_script(false);
        assert!(script.contains("FERRUM_MESH_UDP_OUTBOUND"));
        assert!(
            script.contains("ip6tables")
                && script.contains(UDP_FAIL_CLOSED_CHAIN_A)
                && script.contains(UDP_FAIL_CLOSED_CHAIN_B),
            "v4-only teardown must reap guards from an earlier v6-enabled run: {script}"
        );
        assert!(
            !script.contains("ip -6") && !script.contains("FERRUM_MESH_UDP_OUTBOUND_V6"),
            "normal v6 capture teardown remains disabled: {script}"
        );
    }

    #[test]
    fn udp_capture_disabled_by_default_emits_no_mangle_or_tproxy() {
        // The default (UDP off) plan must contain NO mangle/TPROXY/ip-routing
        // rules — Stage 2 is inert until explicitly enabled.
        let mut config = CaptureConfig::explicit(15006, 15001);
        config.mode = CaptureMode::Iptables;
        assert!(!config.udp_capture_enabled);
        assert_eq!(config.udp_outbound_port, DEFAULT_UDP_OUTBOUND_PORT);
        assert_eq!(config.tproxy_mark, DEFAULT_TPROXY_MARK);

        let plan = IptablesPlan::for_config(&config).unwrap();
        for cmd in plan.v4_commands.iter().chain(plan.v6_commands.iter()) {
            assert!(
                !cmd.contains("mangle")
                    && !cmd.contains("TPROXY")
                    && !cmd.contains("FERRUM_MESH_UDP")
                    && !cmd.contains("-p udp")
                    && !cmd.contains("ip rule")
                    && !cmd.contains("ip route")
                    && !cmd.contains("fwmark"),
                "UDP-disabled plan must emit no UDP/TPROXY/routing rules: {cmd}"
            );
        }
    }

    #[test]
    fn udp_capture_enabled_emits_mangle_chains_tproxy_and_routing() {
        let config = udp_enabled_iptables_config();
        let plan = IptablesPlan::for_config(&config).unwrap();
        let cmds = &plan.v4_commands;

        // New mangle-table chains are created. Inbound UDP capture stays enabled
        // for LOCAL destinations so unauthenticated UDP cannot bypass the mesh.
        assert!(
            cmds.iter()
                .any(|c| c.contains("-t mangle") && c.contains("-N FERRUM_MESH_UDP_OUTBOUND")),
            "missing UDP outbound mangle chain: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("-t mangle") && c.contains("-N FERRUM_MESH_UDP_INBOUND")),
            "missing UDP inbound mangle chain: {cmds:?}"
        );

        // Catch-all TPROXY jump on both directions, on the UDP port with the mark.
        let tproxy_arg = format!(
            "-j TPROXY --on-port {} --tproxy-mark 0x{:x}/0x{:x}",
            DEFAULT_UDP_OUTBOUND_PORT, DEFAULT_TPROXY_MARK, TPROXY_MARK_MASK
        );
        assert!(
            cmds.iter().any(|c| c.contains("FERRUM_MESH_UDP_OUTBOUND")
                && c.contains("-p udp")
                && c.contains(&tproxy_arg)),
            "missing outbound UDP TPROXY jump: {cmds:?}"
        );

        // mangle PREROUTING jumps for both dst-based chains, plus the reinject chain
        // jump. TPROXY is PREROUTING-only, so the OUTPUT path is MARK-only (codex
        // r6): a `mangle OUTPUT -j FERRUM_MESH_UDP_OUTPUT_MARK` jump MUST exist, but
        // the OUTPUT chain must NEVER jump into a `-j TPROXY` chain (which would be
        // invalid).
        assert!(
            cmds.iter().any(|c| c.contains("-t mangle")
                && c.contains("PREROUTING")
                && c.contains("-j FERRUM_MESH_UDP_OUTBOUND")),
            "missing mangle PREROUTING -> UDP outbound jump: {cmds:?}"
        );
        assert!(
            cmds.iter().any(|c| c.contains("-t mangle")
                && c.contains("PREROUTING")
                && c.contains("-j FERRUM_MESH_UDP_REINJECT")),
            "missing mangle PREROUTING -> UDP reinject jump (codex r6): {cmds:?}"
        );
        // The OUTPUT jump must target the MARK-only chain, NOT a TPROXY chain.
        assert!(
            cmds.iter().any(|c| c.contains("-t mangle")
                && c.contains("-A OUTPUT")
                && c.contains("-j FERRUM_MESH_UDP_OUTPUT_MARK")),
            "missing mangle OUTPUT -> UDP OUTPUT MARK jump (codex r6): {cmds:?}"
        );
        assert!(
            !cmds.iter().any(|c| c.contains("-t mangle")
                && c.contains("-A OUTPUT")
                && c.contains("TPROXY")),
            "mangle OUTPUT must never jump into a TPROXY rule (invalid in OUTPUT): {cmds:?}"
        );

        // Transparent-routing plumbing: a FATAL `command -v ip` preflight (codex
        // r2 fail-closed) + idempotent (delete-before-add) ip rule by explicit
        // priority + ip route local (delete-before-add). The fwmark selector still
        // matches the --tproxy-mark above. The load-bearing ADDs are bare (NOT
        // `command -v ip`-guarded, NOT `|| true`) — they must fail closed.
        assert!(
            cmds.iter()
                .any(|c| c.contains("command -v ip >/dev/null 2>&1")
                    && c.contains("exit 1")
                    && c.contains("iproute2")),
            "missing FATAL `command -v ip || exit 1` preflight for routing: {cmds:?}"
        );
        assert!(
            cmds.iter().any(|c| c
                .contains(&format!("rule add priority {TPROXY_ROUTE_RULE_PRIORITY}"))
                && c.contains("fwmark")
                && c.contains(&format!("lookup {TPROXY_ROUTE_TABLE}"))),
            "missing `ip rule add priority <P> fwmark ... lookup <table>`: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains(&format!("rule del priority {TPROXY_ROUTE_RULE_PRIORITY}"))),
            "missing idempotent `ip rule del priority <P>` before the add: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("route add local 0.0.0.0/0 dev lo")
                    && c.contains(&format!("table {TPROXY_ROUTE_TABLE}"))),
            "missing `ip route add local ... table <table>`: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("route del local 0.0.0.0/0 dev lo")
                    && c.contains(&format!("table {TPROXY_ROUTE_TABLE}"))),
            "missing idempotent `ip route del local ... table <table>` before the add: {cmds:?}"
        );
        // The Ferrum routing table must NOT be Istio's shared inbound-TPROXY
        // table 133 (cleanup of ours must never risk a co-resident Istio table).
        assert_ne!(
            TPROXY_ROUTE_TABLE, 133,
            "Ferrum UDP routing table must not reuse Istio's table 133"
        );
    }

    #[test]
    fn udp_setup_flushes_chains_before_adding_rules() {
        // codex r3: changing FERRUM_MESH_CAPTURE_UDP_PORT / FERRUM_MESH_TPROXY_MARK
        // on reconfiguration must NOT leave a stale rule ahead of the new one. The
        // per-rule `-C ... || -A` guard is exact-match, so a changed rule is
        // appended AFTER the old one and (iptables preserves order) the stale rule
        // black-holes UDP. Setup must FLUSH each UDP chain after creating it and
        // BEFORE adding any rule to it.
        let plan = IptablesPlan::for_config(&udp_enabled_iptables_config()).unwrap();
        let cmds = &plan.v4_commands;

        for chain in [
            "FERRUM_MESH_UDP_OUTBOUND",
            "FERRUM_MESH_UDP_OUTPUT_MARK",
            "FERRUM_MESH_UDP_REINJECT",
            "FERRUM_MESH_UDP_INBOUND",
        ] {
            let flush = cmds
                .iter()
                .position(|c| c.contains("-t mangle") && c.contains(&format!("-F {chain}")))
                .unwrap_or_else(|| panic!("setup missing flush of {chain}: {cmds:?}"));
            // The flush must precede every append/check into this chain so the
            // chain is rebuilt cleanly.
            let first_rule = cmds.iter().position(|c| {
                c.contains("-t mangle")
                    && (c.contains(&format!("-A {chain}")) || c.contains(&format!("-C {chain}")))
            });
            if let Some(first_rule) = first_rule {
                assert!(
                    flush < first_rule,
                    "flush of {chain} must precede its first rule add: {cmds:?}"
                );
            }
        }
    }

    #[test]
    fn udp_setup_ip_rule_and_route_are_idempotent_delete_before_add() {
        // A node-agent fallback crash before cleanup then a re-run must not stack
        // a duplicate `ip rule`: setup deletes by explicit priority before adding,
        // and deletes the exact route before adding it.
        let plan = IptablesPlan::for_config(&udp_enabled_iptables_config()).unwrap();
        let cmds = &plan.v4_commands;

        let rule_del = cmds
            .iter()
            .position(|c| c.contains(&format!("rule del priority {TPROXY_ROUTE_RULE_PRIORITY}")))
            .expect("ip rule del present");
        let rule_add = cmds
            .iter()
            .position(|c| c.contains(&format!("rule add priority {TPROXY_ROUTE_RULE_PRIORITY}")))
            .expect("ip rule add present");
        assert!(
            rule_del < rule_add,
            "ip rule del must precede add for idempotency: {cmds:?}"
        );

        let route_del = cmds
            .iter()
            .position(|c| c.contains("route del local 0.0.0.0/0 dev lo"))
            .expect("ip route del present");
        let route_add = cmds
            .iter()
            .position(|c| c.contains("route add local 0.0.0.0/0 dev lo"))
            .expect("ip route add present");
        assert!(
            route_del < route_add,
            "ip route del must precede add for idempotency: {cmds:?}"
        );
    }

    // codex r2 finding 3: the RPDB is priority-ordered and the kernel's built-in
    // `main` table rule is priority 32766. The Ferrum fwmark rule MUST sit BELOW
    // it (lower number = evaluated first), or `main` resolves the marked datagram
    // to its normal route before the fwmark lookup steers it to local delivery —
    // captured UDP would black-hole. Compile-time assertion (the value is a
    // const), so a regression to a >=32766 priority fails the build.
    const _: () = assert!(
        TPROXY_ROUTE_RULE_PRIORITY < 32766,
        "fwmark ip-rule priority must be below the kernel `main` rule (32766)"
    );
    // The routing TABLE number is intentionally NOT the rule priority — they are
    // separate concepts (table stays the high Ferrum-owned constant).
    const _: () = assert!(
        TPROXY_ROUTE_TABLE as u32 != TPROXY_ROUTE_RULE_PRIORITY,
        "rule priority must be separate from the routing table number"
    );

    #[test]
    fn udp_prerouting_emits_outbound_and_inbound_jumps() {
        // The OUTBOUND and INBOUND chains are jumped from `mangle PREROUTING`
        // (TPROXY is PREROUTING-only). The inbound jump keeps pod-destined UDP
        // from bypassing mesh identity and authorization.
        let plan = IptablesPlan::for_config(&udp_enabled_iptables_config()).unwrap();
        let cmds = &plan.v4_commands;

        assert!(
            cmds.iter().any(|c| {
                c.contains("-t mangle")
                    && c.contains("PREROUTING")
                    && c.contains("-j FERRUM_MESH_UDP_OUTBOUND")
            }),
            "missing PREROUTING -> UDP outbound jump: {cmds:?}"
        );
        assert!(
            cmds.iter().any(|c| {
                c.contains("-t mangle")
                    && c.contains("PREROUTING")
                    && c.contains("-j FERRUM_MESH_UDP_INBOUND")
            }),
            "missing PREROUTING -> UDP inbound jump: {cmds:?}"
        );
    }

    #[test]
    fn udp_chains_are_direction_scoped_by_dst_addrtype() {
        // codex r2 finding 2: the two PREROUTING chains stay direction-disjoint by
        // destination address type (the pod-IP-agnostic mirror of the TCP chains'
        // hook separation). Outbound TPROXY = `! --dst-type LOCAL` (remote dest);
        // the inbound catch-all = `--dst-type LOCAL` (the pod's own IP).
        let plan = IptablesPlan::for_config(&udp_enabled_iptables_config()).unwrap();
        let cmds = &plan.v4_commands;

        assert!(
            cmds.iter().any(|c| c.contains("FERRUM_MESH_UDP_OUTBOUND")
                && c.contains("-m addrtype ! --dst-type LOCAL")
                && c.contains("-j TPROXY")),
            "outbound UDP TPROXY must be scoped to a non-local destination: {cmds:?}"
        );
        assert!(
            cmds.iter().any(|c| c.contains("FERRUM_MESH_UDP_INBOUND")
                && c.contains("-m addrtype --dst-type LOCAL")
                && c.contains("-j TPROXY")),
            "inbound UDP TPROXY must be scoped to a local destination: {cmds:?}"
        );
    }

    #[test]
    fn udp_routing_fails_closed_when_ip_unavailable() {
        // codex r2 finding 1: TPROXY local delivery is useless without the
        // `ip rule`/`ip route` plumbing. When UDP capture is enabled the setup
        // must (a) fatally preflight `command -v ip` BEFORE installing any UDP
        // rule, and (b) NOT `|| true` the load-bearing routing ADDs.
        let plan = IptablesPlan::for_config(&udp_enabled_iptables_config()).unwrap();
        let cmds = &plan.v4_commands;
        let script = plan.script();

        // (a) Fatal `command -v ip` preflight present, and ordered before any UDP
        // mangle/TPROXY rule and before the routing adds.
        let preflight = cmds
            .iter()
            .position(|c| {
                c.contains("command -v ip >/dev/null 2>&1")
                    && c.contains("exit 1")
                    && c.contains("iproute2")
            })
            .expect("fatal `command -v ip` preflight");
        let first_udp_rule = cmds
            .iter()
            .position(|c| c.contains("FERRUM_MESH_UDP") || c.contains("-p udp"))
            .expect("a UDP rule");
        assert!(
            preflight < first_udp_rule,
            "fatal `command -v ip` preflight must precede any UDP rule (install together or not at all): {cmds:?}"
        );
        let rule_add = cmds
            .iter()
            .position(|c| c.contains(&format!("rule add priority {TPROXY_ROUTE_RULE_PRIORITY}")))
            .expect("ip rule add");
        assert!(
            preflight < rule_add,
            "preflight must precede the routing add: {cmds:?}"
        );

        // (b) Load-bearing ADDs are NOT `|| true` (must fail the `set -e` script).
        for needle in ["rule add priority", "route add local"] {
            let add = cmds
                .iter()
                .find(|c| c.contains(needle))
                .unwrap_or_else(|| panic!("missing `{needle}` command: {cmds:?}"));
            assert!(
                !add.contains("|| true"),
                "load-bearing routing add must NOT be `|| true` (fail closed): {add}"
            );
        }
        // The delete-before-add (idempotence) DOES stay best-effort.
        for needle in ["rule del priority", "route del local"] {
            let del = cmds
                .iter()
                .find(|c| c.contains(needle))
                .unwrap_or_else(|| panic!("missing `{needle}` command: {cmds:?}"));
            assert!(
                del.contains("|| true"),
                "idempotence delete must stay best-effort (`|| true`): {del}"
            );
        }

        // The fatal preflight survives into the `set -e` script (it is the gate
        // that makes `ip`-missing exit non-zero before installing TPROXY).
        assert!(
            script.contains("command -v ip >/dev/null 2>&1")
                && script.contains("iproute2 (ip) is required"),
            "setup script must carry the fatal `command -v ip` preflight: {script}"
        );
    }

    #[test]
    fn udp_capture_mirrors_exclude_rules_and_scopes_owner_match_to_output() {
        let mut config = udp_enabled_iptables_config();
        config.exclude_cidrs = vec!["10.0.0.0/8".to_string()];
        config.exclude_ports = vec![53];
        config.exclude_inbound_ports = vec![5353];

        let plan = IptablesPlan::for_config(&config).unwrap();
        let cmds = &plan.v4_commands;

        assert!(
            cmds.iter().any(|c| c.contains("FERRUM_MESH_UDP_OUTBOUND")
                && c.contains("-p udp -d 10.0.0.0/8 -j RETURN")),
            "UDP outbound exclude CIDR RETURN missing: {cmds:?}"
        );
        assert!(
            cmds.iter().any(|c| c.contains("FERRUM_MESH_UDP_OUTBOUND")
                && c.contains("-p udp --dport 53 -j RETURN")),
            "UDP outbound exclude port RETURN missing: {cmds:?}"
        );
        // The OUTPUT MARK chain mirrors the SAME exclude rules (codex r6) so a
        // locally-generated egress to an excluded CIDR/port is not marked/looped.
        assert!(
            cmds.iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
                    && c.contains("-p udp -d 10.0.0.0/8 -j RETURN")),
            "UDP OUTPUT MARK exclude CIDR RETURN missing: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
                    && c.contains("-p udp --dport 53 -j RETURN")),
            "UDP OUTPUT MARK exclude port RETURN missing: {cmds:?}"
        );
        // Owner-match self-exclusion is OUTPUT-context ONLY (codex r6): it MUST
        // appear in the OUTPUT MARK chain (locally-generated egress sees the
        // originating socket) and MUST NOT appear in any PREROUTING-reached chain
        // (OUTBOUND/INBOUND/REINJECT — owner-match is invalid there). (The TCP `nat`
        // chain still uses `-m owner` legitimately, so scope this to the UDP chains.)
        assert!(
            cmds.iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
                    && c.contains(&format!(
                        "-m owner --uid-owner {} -j RETURN",
                        DEFAULT_PROXY_UID
                    ))),
            "UDP OUTPUT MARK chain must carry the proxy-UID owner RETURN: {cmds:?}"
        );
        for chain in [
            "FERRUM_MESH_UDP_OUTBOUND",
            "FERRUM_MESH_UDP_INBOUND",
            "FERRUM_MESH_UDP_REINJECT",
        ] {
            assert!(
                !cmds
                    .iter()
                    .any(|c| c.contains(chain) && c.contains("-m owner")),
                "PREROUTING-reached chain {chain} must NOT emit `-m owner` (invalid context): {cmds:?}"
            );
        }

        assert!(
            cmds.iter().any(|c| c.contains("FERRUM_MESH_UDP_INBOUND")
                && c.contains("-p udp --dport 5353 -j RETURN")),
            "UDP inbound exclude port RETURN missing: {cmds:?}"
        );
    }

    #[test]
    fn udp_output_mark_loop_captures_locally_generated_egress() {
        // codex r6: the pod's OWN locally-generated UDP egress goes OUTPUT ->
        // POSTROUTING and never PREROUTING, so it is captured via an OUTPUT MARK
        // chain -> fwmark reroute to lo -> a mark-match PREROUTING TPROXY rule (in
        // the reinject chain). Assert the whole loop is wired in the injector
        // (pod-netns) path.
        let config = udp_enabled_iptables_config();
        assert!(!config.host_netns, "this test exercises the pod-netns path");
        let plan = IptablesPlan::for_config(&config).unwrap();
        let cmds = &plan.v4_commands;

        let mark_arg = format!("0x{:x}/0x{:x}", DEFAULT_TPROXY_MARK, TPROXY_MARK_MASK);

        // (a) The OUTPUT MARK chain is created and jumped from `mangle OUTPUT`.
        assert!(
            cmds.iter()
                .any(|c| c.contains("-t mangle") && c.contains("-N FERRUM_MESH_UDP_OUTPUT_MARK")),
            "missing OUTPUT MARK chain creation: {cmds:?}"
        );
        assert!(
            cmds.iter().any(|c| c.contains("-t mangle")
                && c.contains("-A OUTPUT")
                && c.contains("-p udp -j FERRUM_MESH_UDP_OUTPUT_MARK")),
            "missing `mangle OUTPUT -j FERRUM_MESH_UDP_OUTPUT_MARK` jump: {cmds:?}"
        );

        // (b) The OUTPUT MARK chain leads with an anti-loop mark RETURN and a
        // proxy-UID owner RETURN, then MARKs egress with the TPROXY fwmark (NOT
        // TPROXY — invalid in OUTPUT).
        assert!(
            cmds.iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
                    && c.contains(&format!("-m mark --mark {mark_arg} -j RETURN"))),
            "missing anti-loop mark RETURN at top of OUTPUT MARK chain: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
                    && c.contains(&format!("-j MARK --set-mark {mark_arg}"))),
            "missing `-j MARK --set-mark <mark>` rule in OUTPUT MARK chain: {cmds:?}"
        );
        assert!(
            !cmds
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK") && c.contains("TPROXY")),
            "OUTPUT MARK chain must MARK, never TPROXY (invalid in OUTPUT): {cmds:?}"
        );

        // (c) The reinject chain holds the mark-match TPROXY rule and is jumped from
        // PREROUTING BEFORE the dst-based OUTBOUND/INBOUND chains (so the looped
        // datagram is TPROXY'd once, never double-processed by the dst-based chain).
        let reinject_tproxy = format!(
            "-p udp -m mark --mark {mark_arg} -j TPROXY --on-port {} --tproxy-mark {mark_arg}",
            DEFAULT_UDP_OUTBOUND_PORT
        );
        assert!(
            cmds.iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_REINJECT") && c.contains(&reinject_tproxy)),
            "missing mark-match TPROXY rule in reinject chain: {cmds:?}"
        );
        let reinject_jump = cmds
            .iter()
            .position(|c| {
                c.contains("-t mangle")
                    && c.contains("PREROUTING")
                    && c.contains("-j FERRUM_MESH_UDP_REINJECT")
            })
            .expect("PREROUTING -> reinject jump");
        let outbound_jump = cmds
            .iter()
            .position(|c| {
                c.contains("-t mangle")
                    && c.contains("PREROUTING")
                    && c.contains("-j FERRUM_MESH_UDP_OUTBOUND")
            })
            .expect("PREROUTING -> outbound jump");
        let inbound_jump = cmds
            .iter()
            .position(|c| {
                c.contains("-t mangle")
                    && c.contains("PREROUTING")
                    && c.contains("-j FERRUM_MESH_UDP_INBOUND")
            })
            .expect("PREROUTING -> inbound jump");
        assert!(
            reinject_jump < outbound_jump && outbound_jump < inbound_jump,
            "PREROUTING jump order must be reinject, outbound, inbound: {cmds:?}"
        );

        // (d) Host-netns (node-agent) path emits NO UDP rules at all — including no
        // OUTPUT MARK chain / OUTPUT jump — because the addrtype direction split is
        // wrong in the host netns (round-5 limitation, preserved).
        let mut host_config = config.clone();
        host_config.host_netns = true;
        let host_plan = IptablesPlan::for_config(&host_config).unwrap();
        for cmd in host_plan
            .v4_commands
            .iter()
            .chain(host_plan.v6_commands.iter())
        {
            assert!(
                !(cmd.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
                    || cmd.contains("FERRUM_MESH_UDP_REINJECT")
                    || cmd.contains("-j MARK --set-mark")
                    || (cmd.contains("-t mangle") && cmd.contains("OUTPUT"))),
                "host-netns path must emit NO UDP OUTPUT MARK / reinject rules: {cmd}"
            );
        }
    }

    #[test]
    fn udp_output_mark_mirrors_outbound_capture_scope() {
        // The OUTPUT MARK chain must mirror the SAME include scoping as the
        // PREROUTING outbound TPROXY chain (codex r6): per-port includes emit a
        // per-port `-j MARK` and the implicit catch-all emits a catch-all `-j MARK`,
        // so OUTPUT capture exactly matches PREROUTING capture.
        // Default config (`include_cidrs = ["0.0.0.0/0"]`, NOT explicit): the
        // OUTPUT MARK chain mirrors the OUTBOUND TPROXY chain's selector exactly —
        // a `-p udp -d 0.0.0.0/0 -m addrtype ! --dst-type LOCAL -j MARK` rule (same
        // `-d 0.0.0.0/0` selector AND the same `! --dst-type LOCAL` egress scope the
        // TPROXY rule carries). Only the jump differs (MARK vs TPROXY).
        let default_plan = IptablesPlan::for_config(&udp_enabled_iptables_config()).unwrap();
        let mark_arg = format!("0x{:x}/0x{:x}", DEFAULT_TPROXY_MARK, TPROXY_MARK_MASK);
        // The OUTBOUND TPROXY chain carries `-p udp -d 0.0.0.0/0 -m addrtype ! ...`.
        assert!(
            default_plan
                .v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTBOUND")
                    && c.contains("-p udp -d 0.0.0.0/0 -m addrtype ! --dst-type LOCAL -j TPROXY")),
            "default OUTBOUND TPROXY rule shape changed: {:?}",
            default_plan.v4_commands
        );
        // The OUTPUT MARK chain mirrors the SAME `-p udp -d 0.0.0.0/0` selector AND
        // the SAME `! --dst-type LOCAL` egress scope, with a MARK jump (codex r9):
        // loopback / the pod's own IP are `--dst-type LOCAL` in OUTPUT and must NOT
        // be marked (else they would be fwmark-rerouted to `lo` + TPROXY-captured);
        // only genuine non-local egress is marked.
        assert!(
            default_plan
                .v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
                    && c.contains(&format!(
                        "-p udp -d 0.0.0.0/0 -m addrtype ! --dst-type LOCAL -j MARK --set-mark {mark_arg}"
                    ))),
            "OUTPUT MARK must mirror the OUTBOUND selector AND `! --dst-type LOCAL` scope: {:?}",
            default_plan.v4_commands
        );
        // Every OUTPUT MARK `-j MARK` rule MUST carry the `! --dst-type LOCAL` scope
        // (codex r9 — exclude loopback / self), and NONE may carry the inbound
        // `--dst-type LOCAL` (without the `!`) discriminator. We assert each marking
        // rule contains `addrtype ! --dst-type LOCAL` and that no marking rule
        // carries a bare (non-negated) `--dst-type LOCAL`.
        let mark_rules: Vec<&String> = default_plan
            .v4_commands
            .iter()
            .filter(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK") && c.contains("-j MARK"))
            .collect();
        assert!(
            !mark_rules.is_empty(),
            "expected at least one OUTPUT MARK marking rule: {:?}",
            default_plan.v4_commands
        );
        for rule in &mark_rules {
            assert!(
                rule.contains("-m addrtype ! --dst-type LOCAL"),
                "OUTPUT MARK rule must exclude LOCAL (loopback/self) destinations: {rule}"
            );
            assert!(
                !rule.contains("addrtype --dst-type LOCAL"),
                "OUTPUT MARK rule must NOT carry the inbound (non-negated) `--dst-type LOCAL`: {rule}"
            );
        }

        // Per-port includes: a `--dport` MARK rule per port (each carrying the
        // `! --dst-type LOCAL` egress scope), and NO catch-all MARK.
        let mut port_config = udp_enabled_iptables_config();
        port_config.include_outbound_ports = vec![5432, 9092];
        let port_plan = IptablesPlan::for_config(&port_config).unwrap();
        for port in [5432, 9092] {
            assert!(
                port_plan
                    .v4_commands
                    .iter()
                    .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
                        && c.contains(&format!(
                            "-p udp --dport {port} -m addrtype ! --dst-type LOCAL -j MARK --set-mark {mark_arg}"
                        ))),
                "per-port OUTPUT MARK (with `! --dst-type LOCAL`) missing for {port}: {:?}",
                port_plan.v4_commands
            );
        }
        // Every per-port MARK rule still excludes LOCAL destinations.
        for rule in port_plan
            .v4_commands
            .iter()
            .filter(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK") && c.contains("-j MARK"))
        {
            assert!(
                rule.contains("-m addrtype ! --dst-type LOCAL"),
                "per-port OUTPUT MARK rule must exclude LOCAL (loopback/self): {rule}"
            );
        }
        assert!(
            !port_plan
                .v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK")
                    && c.contains("-j MARK")
                    && !c.contains("--dport")),
            "implicit catch-all MARK must not fire when includeOutboundPorts narrows: {:?}",
            port_plan.v4_commands
        );
    }

    #[test]
    fn udp_capture_per_port_tproxy_when_include_ports_set() {
        let mut config = udp_enabled_iptables_config();
        config.include_outbound_ports = vec![5432, 9092];

        let plan = IptablesPlan::for_config(&config).unwrap();
        for port in [5432, 9092] {
            assert!(
                plan.v4_commands.iter().any(|c| c.contains(&format!(
                    "-p udp --dport {port} -m addrtype ! --dst-type LOCAL -j TPROXY --on-port {}",
                    DEFAULT_UDP_OUTBOUND_PORT
                ))),
                "per-port UDP TPROXY (non-local-scoped) missing for {port}: {:?}",
                plan.v4_commands
            );
        }
        // includeOutboundPorts without explicit include CIDRs must not also emit
        // an OUTBOUND catch-all (no `--dport`/`-d` narrowing) `-p udp ... -j TPROXY`
        // (mirrors the TCP narrowing semantics). The INBOUND chain keeps its
        // protocol-wide catch-all, so scope this check to the outbound chain.
        assert!(
            !plan
                .v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTBOUND")
                    && c.contains("-j TPROXY")
                    && !c.contains("--dport")
                    && !c.contains("-d ")),
            "implicit catch-all outbound UDP TPROXY must not fire when includeOutboundPorts narrows: {:?}",
            plan.v4_commands
        );
    }

    #[test]
    fn udp_capture_partitions_ipv4_and_ipv6() {
        let mut config = udp_enabled_iptables_config();
        config.include_cidrs = vec!["172.16.0.0/12".to_string(), "2001:db8::/32".to_string()];
        config.include_cidrs_explicit = true;

        let plan = IptablesPlan::for_config(&config).unwrap();

        // IPv4 TPROXY rules use `iptables` + IPv4 routing; no IPv6 leakage. The
        // outbound CIDR rule carries the non-local destination scope.
        assert!(
            plan.v4_commands
                .iter()
                .any(|c| c.contains("iptables -t mangle")
                    && c.contains(
                        "-p udp -d 172.16.0.0/12 -m addrtype ! --dst-type LOCAL -j TPROXY"
                    )),
            "IPv4 UDP TPROXY CIDR rule missing: {:?}",
            plan.v4_commands
        );
        assert!(
            plan.v4_commands.iter().any(|c| c.contains(&format!(
                "ip rule add priority {TPROXY_ROUTE_RULE_PRIORITY} fwmark"
            )) && !c.contains("ip -6")),
            "IPv4 transparent routing must use `ip` (not `ip -6`): {:?}",
            plan.v4_commands
        );
        assert!(
            !plan
                .v4_commands
                .iter()
                .any(|c| c.contains("::/") || c.contains("2001:db8") || c.contains("ip -6")),
            "IPv6 UDP rules must not appear in IPv4 commands: {:?}",
            plan.v4_commands
        );

        // IPv6 TPROXY rules use `ip6tables -t mangle` + `ip -6` routing.
        assert!(
            plan.v6_commands
                .iter()
                .any(|c| c.contains("ip6tables -t mangle")
                    && c.contains(
                        "-p udp -d 2001:db8::/32 -m addrtype ! --dst-type LOCAL -j TPROXY"
                    )),
            "IPv6 UDP TPROXY CIDR rule missing: {:?}",
            plan.v6_commands
        );
        assert!(
            plan.v6_commands
                .iter()
                .any(|c| c.contains(&format!(
                    "ip -6 rule add priority {TPROXY_ROUTE_RULE_PRIORITY} fwmark"
                )) && c.contains(&format!("lookup {TPROXY_ROUTE_TABLE}"))),
            "IPv6 transparent routing rule missing: {:?}",
            plan.v6_commands
        );
        assert!(
            plan.v6_commands
                .iter()
                .any(|c| c.contains("ip -6 route add local ::/0 dev lo")),
            "IPv6 local route missing: {:?}",
            plan.v6_commands
        );
    }

    #[test]
    fn cleanup_removes_udp_tproxy_chains_and_routing() {
        let cleanup = IptablesPlan::cleanup_commands(true);

        // mangle chain teardown (jumps, flush, delete) for ALL FOUR UDP chains —
        // the dst-based PREROUTING pair plus the OUTPUT MARK + reinject chains
        // (codex r6).
        for chain in [
            "FERRUM_MESH_UDP_INBOUND",
            "FERRUM_MESH_UDP_OUTBOUND",
            "FERRUM_MESH_UDP_OUTPUT_MARK",
            "FERRUM_MESH_UDP_REINJECT",
        ] {
            assert!(
                cleanup
                    .iter()
                    .any(|c| c.contains("-t mangle") && c.contains(&format!("-F {chain}"))),
                "cleanup missing flush of {chain}"
            );
            assert!(
                cleanup
                    .iter()
                    .any(|c| c.contains("-t mangle") && c.contains(&format!("-X {chain}"))),
                "cleanup missing delete of {chain}"
            );
        }
        // PREROUTING jump deletes for the three PREROUTING-jumped chains.
        for chain in [
            "FERRUM_MESH_UDP_INBOUND",
            "FERRUM_MESH_UDP_OUTBOUND",
            "FERRUM_MESH_UDP_REINJECT",
        ] {
            assert!(
                cleanup.iter().any(|c| c.contains("-t mangle")
                    && c.contains("PREROUTING")
                    && c.contains("-D")
                    && c.contains(chain)),
                "cleanup missing mangle PREROUTING jump delete for {chain}"
            );
        }
        // The `mangle OUTPUT -j FERRUM_MESH_UDP_OUTPUT_MARK` jump (codex r6) MUST be
        // deleted — and the OUTPUT delete must target the MARK chain, never a TPROXY
        // chain (none was installed there).
        assert!(
            cleanup.iter().any(|c| c.contains("-t mangle")
                && c.contains("-D OUTPUT")
                && c.contains("-j FERRUM_MESH_UDP_OUTPUT_MARK")),
            "cleanup missing mangle OUTPUT MARK jump delete (codex r6): {cleanup:?}"
        );
        assert!(
            !cleanup.iter().any(|c| c.contains("-t mangle")
                && c.contains("-D OUTPUT")
                && c.contains("TPROXY")),
            "cleanup OUTPUT delete must not reference a TPROXY chain: {cleanup:?}"
        );

        // Routing teardown deletes ONLY the EXACT Ferrum-owned rule (by explicit
        // priority) + exact route — never `ip rule del lookup` / `ip route flush
        // table` (which could drop a co-resident route, e.g. an Istio table).
        // Cleanup deletes are best-effort (`|| true`), not `command -v ip`-gated.
        assert!(
            cleanup.iter().any(|c| c
                .contains(&format!("rule del priority {TPROXY_ROUTE_RULE_PRIORITY}"))
                && c.contains(&format!("lookup {TPROXY_ROUTE_TABLE}"))),
            "cleanup missing exact `ip rule del priority <P> lookup <table>`: {cleanup:?}"
        );
        assert!(
            cleanup
                .iter()
                .any(|c| c.contains("route del local 0.0.0.0/0 dev lo")
                    && c.contains(&format!("table {TPROXY_ROUTE_TABLE}"))),
            "cleanup missing exact `ip route del local ... table <table>`: {cleanup:?}"
        );
        assert!(
            !cleanup
                .iter()
                .any(|c| c.contains("route flush table") || c.contains("rule del lookup")),
            "cleanup must NOT flush a table or delete-by-lookup (shared-table hazard): {cleanup:?}"
        );
        // Every command tolerates missing state; dedicated guard loops still
        // propagate resource errors instead of hiding an active DROP jump.
        for cmd in &cleanup {
            assert!(
                tolerates_missing_cleanup_state(cmd),
                "UDP cleanup command must tolerate missing state: {cmd}"
            );
        }
    }

    #[test]
    fn cleanup_v6_split_separates_raw_ip_routing_from_ip6tables_tables() {
        // codex r3: the raw `ip -6 rule/route del` teardown must be in `ip_routing`
        // (emitted unconditionally by the node-agent) and NOT in `iptables` (which
        // the node-agent guards behind an `ip6tables` availability probe). Wrapping
        // the `ip -6` teardown in that probe would leak the fwmark rule + local
        // route when `ip6tables` is missing.
        let split = IptablesPlan::cleanup_v6_split(true);

        // The raw `ip -6` rule/route teardown lives in `ip_routing`.
        assert!(
            split.ip_routing.iter().any(|c| c.contains("ip -6 rule del")
                && c.contains(&format!("lookup {TPROXY_ROUTE_TABLE}"))),
            "v6 ip_routing must carry `ip -6 rule del ... lookup <table>`: {:?}",
            split.ip_routing
        );
        assert!(
            split
                .ip_routing
                .iter()
                .any(|c| c.contains("ip -6 route del local ::/0 dev lo")),
            "v6 ip_routing must carry `ip -6 route del local ::/0 dev lo`: {:?}",
            split.ip_routing
        );
        // The `iptables`/table portion must NOT contain any raw `ip -6` routing.
        assert!(
            !split
                .iptables
                .iter()
                .any(|c| c.contains("ip -6 rule") || c.contains("ip -6 route")),
            "v6 iptables (table) portion must not contain raw `ip -6` routing: {:?}",
            split.iptables
        );
        // The table portion still tears down the mangle chains (ip6tables-guarded).
        assert!(
            split
                .iptables
                .iter()
                .any(|c| c.contains("ip6tables") && c.contains("FERRUM_MESH_UDP")),
            "v6 iptables portion must tear down the UDP mangle chains: {:?}",
            split.iptables
        );
    }

    #[test]
    fn cleanup_v6_split_routing_empty_when_udp_disabled() {
        // When UDP capture was never enabled, there is no routing state to tear
        // down (gated like the v4 path); both halves carry only the TCP nat-chain
        // teardown and no `ip -6` routing.
        let split = IptablesPlan::cleanup_v6_split(false);
        assert!(
            split.ip_routing.is_empty(),
            "UDP-disabled v6 cleanup must emit no routing teardown: {:?}",
            split.ip_routing
        );
    }

    #[test]
    fn cleanup_gated_off_emits_no_udp_or_routing_teardown() {
        // When this install never enabled UDP capture, cleanup must not touch any
        // UDP mangle chain OR routing state it never created (codex r1).
        let cleanup = IptablesPlan::cleanup_commands(false);
        for cmd in &cleanup {
            assert!(
                !cmd.contains("FERRUM_MESH_UDP")
                    && !cmd.contains("mangle")
                    && !cmd.contains("ip rule")
                    && !cmd.contains("ip route")
                    && !cmd.contains(&format!("table {TPROXY_ROUTE_TABLE}"))
                    && !cmd.contains(&format!("priority {TPROXY_ROUTE_RULE_PRIORITY}")),
                "UDP-disabled cleanup must emit no UDP/mangle/routing teardown: {cmd}"
            );
        }
        // The TCP nat-chain teardown still runs.
        assert!(
            cleanup
                .iter()
                .any(|c| c.contains("FERRUM_MESH_INBOUND") || c.contains("FERRUM_MESH_OUTBOUND")),
            "UDP-disabled cleanup must still tear down the TCP nat chains: {cleanup:?}"
        );
    }

    #[test]
    fn udp_capture_v6_suppressed_when_ip6tables_disabled() {
        let mut config = udp_enabled_iptables_config();
        config.ip6tables_mode = Ip6TablesMode::Disabled;
        config.include_cidrs = vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()];

        let plan = IptablesPlan::for_config(&config).unwrap();
        assert!(
            plan.v6_commands.is_empty(),
            "disabled ip6tables must suppress IPv6 UDP TPROXY rules: {:?}",
            plan.v6_commands
        );
        // IPv4 UDP rules still emit.
        assert!(
            plan.v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTBOUND") && c.contains("TPROXY")),
            "IPv4 UDP TPROXY must remain when ip6tables disabled: {:?}",
            plan.v4_commands
        );
    }

    #[test]
    fn udp_capture_ipv6_only_includes_emit_no_ipv4_catch_all() {
        // codex r4 (finding #1): with an IPv6-only EXPLICIT include set, the IPv4
        // family has no include CIDR but `include_cidrs_explicit` is still true.
        // Unlike the TCP REDIRECT path (which fails closed to an IPv4 catch-all
        // delivering to the existing outbound listener), the UDP path must SKIP the
        // unqualified IPv4 `-j TPROXY` catch-all entirely — an unqualified UDP
        // TPROXY would divert ALL IPv4 UDP (DNS included) into the marked routing
        // table though only IPv6 was selected, black-holing it (no Stage 3 listener
        // yet). Capturing nothing for the unselected family is the safe failure.
        let mut config = udp_enabled_iptables_config();
        config.include_cidrs = vec!["fd00::/8".to_string()];
        config.include_cidrs_explicit = true;

        let plan = IptablesPlan::for_config(&config).unwrap();

        // The IPv4 family must emit no OUTBOUND UDP catch-all or MARK rule when
        // only IPv6 CIDRs are selected. Inbound LOCAL capture is still emitted for
        // the active IPv4 family so pod-destined UDP fail-closes behind the mesh
        // relay instead of bypassing mTLS/authz.
        assert!(
            !plan
                .v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTBOUND") && c.contains("-j TPROXY")),
            "IPv6-only explicit includes must not emit IPv4 outbound UDP TPROXY state: {:?}",
            plan.v4_commands
        );
        assert!(
            !plan
                .v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTPUT_MARK") && c.contains("-j MARK")),
            "IPv6-only explicit includes must not MARK IPv4 outbound UDP egress: {:?}",
            plan.v4_commands
        );
        assert!(
            plan.v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_INBOUND")
                    && c.contains("-m addrtype --dst-type LOCAL")
                    && c.contains("-j TPROXY")),
            "IPv4 inbound UDP LOCAL capture must stay installed for fail-closed inbound protection: {:?}",
            plan.v4_commands
        );
        // The TCP IPv4 chains are still present (CIDR scoping is outbound-UDP-only).
        assert!(
            plan.v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_INBOUND") || c.contains("FERRUM_MESH_OUTBOUND")),
            "IPv4 TCP capture chains must remain: {:?}",
            plan.v4_commands
        );
        // The IPv6 family still gets its narrowed TPROXY rule (the selected family).
        assert!(
            plan.v6_commands
                .iter()
                .any(|c| c.contains("ip6tables -t mangle")
                    && c.contains("-p udp -d fd00::/8 -m addrtype ! --dst-type LOCAL -j TPROXY")),
            "IPv6 UDP TPROXY CIDR rule must still be emitted for the selected family: {:?}",
            plan.v6_commands
        );
    }

    #[test]
    fn udp_port_includes_survive_cross_family_catch_all_skip() {
        // codex r5 (finding #2): the cross-family CATCH-ALL skip (codex r4) must
        // NOT also drop family-agnostic `--dport` port includes. With an IPv6-only
        // include CIDR plus an `includeOutboundPorts` port (e.g. DNS/53), the IPv4
        // family is cross-family-skipped for the CIDR catch-all but must STILL emit
        // its IPv4 `--dport 53` TPROXY rule — a port include is not family-scoped.
        let mut config = udp_enabled_iptables_config();
        config.include_cidrs = vec!["fd00::/8".to_string()];
        config.include_cidrs_explicit = true;
        config.include_outbound_ports = vec![53];

        let plan = IptablesPlan::for_config(&config).unwrap();

        // The IPv4 `--dport 53` outbound TPROXY rule MUST be present (the port
        // include survives the catch-all skip).
        assert!(
            plan.v4_commands
                .iter()
                .any(|c| c.contains("iptables -t mangle")
                    && c.contains("FERRUM_MESH_UDP_OUTBOUND")
                    && c.contains(&format!(
                        "-p udp --dport 53 -m addrtype ! --dst-type LOCAL -j TPROXY --on-port {}",
                        DEFAULT_UDP_OUTBOUND_PORT
                    ))),
            "IPv4 --dport port include must survive the cross-family catch-all skip: {:?}",
            plan.v4_commands
        );
        // Because the port include emits an IPv4 UDP rule, the IPv4 family now also
        // gets its mangle chains, PREROUTING jumps, and routing.
        assert!(
            plan.v4_commands
                .iter()
                .any(|c| c.contains("iptables -t mangle")
                    && c.contains("-N FERRUM_MESH_UDP_OUTBOUND")),
            "IPv4 UDP chains must be created when a port include emits a rule: {:?}",
            plan.v4_commands
        );
        assert!(
            plan.v4_commands
                .iter()
                .any(|c| c.contains("ip rule add priority")
                    && c.contains("fwmark")
                    && !c.contains("ip -6")),
            "IPv4 routing must be installed when a port include emits a rule: {:?}",
            plan.v4_commands
        );
        // But the IPv4 family must STILL NOT get an unqualified OUTBOUND
        // catch-all. Inbound `--dst-type LOCAL` capture is deliberately present
        // for fail-closed inbound protection even when the outbound CIDR selector
        // is IPv6-only.
        assert!(
            !plan
                .v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_OUTBOUND")
                    && c.contains("-j TPROXY")
                    && !c.contains("--dport")
                    && !c.contains("-d ")),
            "IPv4 outbound catch-all must stay suppressed for the unselected family: {:?}",
            plan.v4_commands
        );
        assert!(
            plan.v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_INBOUND")
                    && c.contains("-m addrtype --dst-type LOCAL")
                    && c.contains("-j TPROXY")),
            "IPv4 inbound LOCAL capture must stay installed for fail-closed inbound protection: {:?}",
            plan.v4_commands
        );
        // The IPv6 family keeps its CIDR-qualified OUTBOUND rule (it IS the selected
        // family). The port include also fans onto IPv6 (port includes are
        // family-agnostic). Inbound UDP capture also emits the LOCAL catch-all for
        // the selected family so pod-destined UDP remains fail-closed.
        assert!(
            plan.v6_commands
                .iter()
                .any(|c| c.contains("ip6tables -t mangle")
                    && c.contains("-p udp -d fd00::/8 -m addrtype ! --dst-type LOCAL -j TPROXY")),
            "IPv6 selected-family CIDR rule missing: {:?}",
            plan.v6_commands
        );
        assert!(
            plan.v6_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP_INBOUND")
                    && c.contains("-m addrtype --dst-type LOCAL")
                    && c.contains("-j TPROXY")),
            "IPv6 inbound catch-all must protect the selected family: {:?}",
            plan.v6_commands
        );
    }

    #[test]
    fn udp_host_netns_emits_no_udp_tproxy_rules() {
        // codex r5 (finding #1): the node-agent runs `hostNetwork: true` (host
        // netns), where the `addrtype --dst-type LOCAL` direction split is wrong
        // (pod IPs are FORWARDED, not LOCAL). The host-netns iptables fallback must
        // therefore emit NO UDP TPROXY rules at all (eBPF is the supported
        // node-agent UDP path) rather than silently mis-capturing inbound as
        // outbound. TCP capture is unaffected.
        let mut config = udp_enabled_iptables_config();
        config.host_netns = true;
        config.include_cidrs = vec!["10.0.0.0/8".to_string(), "fd00::/8".to_string()];
        config.include_cidrs_explicit = true;
        config.include_outbound_ports = vec![53];

        let plan = IptablesPlan::for_config(&config).unwrap();

        for cmd in plan.v4_commands.iter().chain(plan.v6_commands.iter()) {
            assert!(
                !cmd.contains("mangle")
                    && !cmd.contains("TPROXY")
                    && !cmd.contains("FERRUM_MESH_UDP")
                    && !cmd.contains("-p udp")
                    && !cmd.contains("fwmark")
                    && !cmd.starts_with("ip rule")
                    && !cmd.starts_with("ip -6 rule")
                    && !cmd.starts_with("ip route")
                    && !cmd.starts_with("ip -6 route"),
                "host-netns UDP-enabled plan must emit no UDP/TPROXY/routing rules: {cmd}"
            );
        }
        // TCP capture chains MUST remain — only the UDP TPROXY path is suppressed.
        assert!(
            plan.v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_INBOUND") || c.contains("FERRUM_MESH_OUTBOUND")),
            "host-netns plan must keep TCP capture chains: {:?}",
            plan.v4_commands
        );
        // The pod-netns (injector) equivalent DOES emit UDP rules — confirm the
        // suppression is keyed strictly on `host_netns`.
        let mut pod_config = config.clone();
        pod_config.host_netns = false;
        let pod_plan = IptablesPlan::for_config(&pod_config).unwrap();
        assert!(
            pod_plan
                .v4_commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_UDP")),
            "pod-netns plan with the same config must still emit UDP rules: {:?}",
            pod_plan.v4_commands
        );
    }

    #[test]
    fn udp_routing_installed_before_prerouting_jumps() {
        // codex r5 (finding #3): the injector init container runs the whole `set -e`
        // script with NO cleanup trap, so the routing plumbing (`ip rule`/`ip
        // route`) must be installed BEFORE the `mangle PREROUTING` jumps that start
        // steering UDP into the chains. Otherwise an `ip rule`/`ip route` failure
        // after the jumps were appended leaves TPROXY live without policy routing —
        // a half-installed black-hole.
        let plan = IptablesPlan::for_config(&udp_enabled_iptables_config()).unwrap();
        let cmds = &plan.v4_commands;

        let route_add = cmds
            .iter()
            .position(|c| c.contains(&format!("rule add priority {TPROXY_ROUTE_RULE_PRIORITY}")))
            .expect("ip rule add present");
        let local_route_add = cmds
            .iter()
            .position(|c| c.contains("route add local 0.0.0.0/0 dev lo"))
            .expect("ip route add present");
        let outbound_jump = cmds
            .iter()
            .position(|c| {
                c.contains("-t mangle")
                    && c.contains("PREROUTING")
                    && c.contains("-j FERRUM_MESH_UDP_OUTBOUND")
            })
            .expect("PREROUTING -> UDP outbound jump");

        // Routing plumbing must precede the first dst-based PREROUTING jump.
        assert!(
            route_add < outbound_jump,
            "fwmark `ip rule add` must precede the PREROUTING jump: {cmds:?}"
        );
        assert!(
            local_route_add < outbound_jump,
            "`ip route add local` must precede the PREROUTING jump: {cmds:?}"
        );
    }

    #[test]
    fn udp_setup_rule_delete_is_priority_keyed_not_mark_keyed() {
        // codex r4 (finding #2): the delete-before-add for the fwmark `ip rule`
        // must delete by the STABLE Ferrum-owned PRIORITY + table only — NOT keyed
        // on the (operator-overridable) mark value. Otherwise a changed
        // `FERRUM_MESH_TPROXY_MARK` leaves the OLD mark's priority-100 rule in
        // place (the new-mark-keyed delete never matches it) and the old mark keeps
        // routing into table 33133.
        let mut config = udp_enabled_iptables_config();
        config.tproxy_mark = 0xABCD;

        let plan = IptablesPlan::for_config(&config).unwrap();

        // The DELETE must be priority+table keyed and must NOT carry a `fwmark`
        // selector (so it matches whatever mark the prior run installed).
        let del = plan
            .v4_commands
            .iter()
            .find(|c| {
                c.contains("ip rule del")
                    && c.contains(&format!("priority {TPROXY_ROUTE_RULE_PRIORITY}"))
                    && c.contains(&format!("lookup {TPROXY_ROUTE_TABLE}"))
            })
            .expect("priority-keyed `ip rule del` must be emitted");
        assert!(
            !del.contains("fwmark"),
            "the fwmark `ip rule` delete-before-add must NOT be keyed on the mark value: {del}"
        );
        assert!(
            del.contains("|| true"),
            "the delete-before-add must stay best-effort: {del}"
        );
        // The ADD still carries the current mark in its fwmark selector.
        assert!(
            plan.v4_commands.iter().any(|c| c.contains("ip rule add")
                && c.contains(&format!("priority {TPROXY_ROUTE_RULE_PRIORITY}"))
                && c.contains("fwmark 0xabcd/")
                && c.contains(&format!("lookup {TPROXY_ROUTE_TABLE}"))),
            "the `ip rule add` must install the current mark: {:?}",
            plan.v4_commands
        );
    }

    #[test]
    fn udp_teardown_split_is_unconditional_and_udp_only() {
        // codex r4 (finding #3, capture half): the dedicated UDP teardown is NOT
        // gated on `udp_capture_enabled` (it takes no flag) and contains ONLY the
        // exact Ferrum-owned UDP state — never the TCP nat chains — so the
        // node-agent can run it unconditionally before setup to reap stale UDP
        // state from a prior UDP-enabled-then-crashed run without disturbing the
        // TCP chains setup is about to rebuild.
        let v4 = IptablesPlan::udp_teardown_split();
        let v6 = IptablesPlan::udp_teardown_v6_split();

        // UDP mangle chain teardown is present (both halves).
        for chain in ["FERRUM_MESH_UDP_INBOUND", "FERRUM_MESH_UDP_OUTBOUND"] {
            assert!(
                v4.iptables
                    .iter()
                    .any(|c| c.contains("-t mangle") && c.contains(&format!("-X {chain}"))),
                "v4 UDP teardown missing delete of {chain}: {:?}",
                v4.iptables
            );
        }
        // The exact Ferrum-owned routing teardown is present and priority-keyed.
        assert!(
            v4.ip_routing.iter().any(|c| c
                .contains(&format!("rule del priority {TPROXY_ROUTE_RULE_PRIORITY}"))
                && c.contains(&format!("lookup {TPROXY_ROUTE_TABLE}"))
                && !c.contains("fwmark")),
            "v4 UDP teardown must delete the fwmark rule by priority (mark-independent): {:?}",
            v4.ip_routing
        );
        assert!(
            v6.ip_routing
                .iter()
                .any(|c| c.contains("ip -6 route del local ::/0 dev lo")
                    && c.contains(&format!("table {TPROXY_ROUTE_TABLE}"))),
            "v6 UDP teardown must delete the exact local route: {:?}",
            v6.ip_routing
        );
        // CRITICAL: the UDP-only teardown must NOT touch the TCP nat chains.
        for cmd in v4.iptables.iter().chain(v6.iptables.iter()) {
            assert!(
                !cmd.contains("-t nat")
                    && !cmd.contains("FERRUM_MESH_INBOUND")
                    && !cmd.contains("FERRUM_MESH_OUTBOUND"),
                "UDP-only teardown must not touch the TCP nat chains: {cmd}"
            );
        }
        // Never flush-by-table or delete-by-lookup (shared-table hazard).
        for cmd in v4
            .iptables
            .iter()
            .chain(v4.ip_routing.iter())
            .chain(v6.iptables.iter())
            .chain(v6.ip_routing.iter())
        {
            assert!(
                !cmd.contains("route flush table") && !cmd.contains("rule del lookup"),
                "UDP teardown must not flush a table or delete-by-lookup: {cmd}"
            );
            assert!(
                tolerates_missing_cleanup_state(cmd) || cmd.contains("if command -v ip6tables"),
                "UDP teardown command must tolerate missing state (or be ip6tables-probe-wrapped): {cmd}"
            );
        }
    }

    #[test]
    fn udp_setup_script_keeps_set_e_and_idempotent_guards() {
        // The TPROXY rules ride the same fail-closed `set -e` script as the TCP
        // rules; the raw `ip` commands must stay self-guarded so they never abort
        // it (missing `iproute2` or an already-present rule).
        let script = IptablesPlan::for_config(&udp_enabled_iptables_config())
            .unwrap()
            .script();
        assert!(script.starts_with("set -e\n"));
        assert!(script.contains("command -v ip >/dev/null 2>&1"));
        assert!(script.contains("FERRUM_MESH_UDP_OUTBOUND"));
        assert!(script.contains("-j TPROXY"));
    }

    #[test]
    fn from_env_defaults_udp_capture_off() {
        with_capture_env(&[], || {
            let config = CaptureConfig::from_env().expect("config");
            assert!(!config.udp_capture_enabled);
            assert_eq!(config.udp_outbound_port, DEFAULT_UDP_OUTBOUND_PORT);
            assert_eq!(config.tproxy_mark, DEFAULT_TPROXY_MARK);
        });
    }

    #[test]
    fn from_env_parses_udp_capture_settings() {
        with_capture_env(
            &[
                ("FERRUM_MESH_CAPTURE_UDP_ENABLED", "true"),
                ("FERRUM_MESH_CAPTURE_UDP_PORT", "16011"),
                ("FERRUM_MESH_TPROXY_MARK", "0x1234"),
            ],
            || {
                let config = CaptureConfig::from_env().expect("config");
                assert!(config.udp_capture_enabled);
                assert_eq!(config.udp_outbound_port, 16011);
                assert_eq!(config.tproxy_mark, 0x1234);
            },
        );
    }

    #[test]
    fn from_env_parses_decimal_tproxy_mark() {
        with_capture_env(&[("FERRUM_MESH_TPROXY_MARK", "1337")], || {
            let config = CaptureConfig::from_env().expect("config");
            assert_eq!(config.tproxy_mark, 1337);
        });
    }

    #[test]
    fn from_env_rejects_invalid_udp_settings() {
        with_capture_env(&[("FERRUM_MESH_CAPTURE_UDP_ENABLED", "maybe")], || {
            assert!(CaptureConfig::from_env().is_err());
        });
        with_capture_env(&[("FERRUM_MESH_CAPTURE_UDP_PORT", "0")], || {
            assert!(CaptureConfig::from_env().is_err());
        });
        with_capture_env(&[("FERRUM_MESH_TPROXY_MARK", "0")], || {
            assert!(CaptureConfig::from_env().is_err());
        });
        with_capture_env(&[("FERRUM_MESH_TPROXY_MARK", "nothex")], || {
            assert!(CaptureConfig::from_env().is_err());
        });
    }

    #[test]
    fn from_env_accepts_repo_wide_bool_forms_for_udp_enabled() {
        // codex r3: `FERRUM_MESH_CAPTURE_UDP_ENABLED` must accept the same forms as
        // every other `FERRUM_MESH_*` bool env (`EnvValue for bool`): case-
        // insensitive `true`/`false` plus `1`/`0`. The previous `bool::from_str`
        // rejected `1`/`0`/`TRUE`.
        for truthy in ["true", "TRUE", "True", "1"] {
            with_capture_env(&[("FERRUM_MESH_CAPTURE_UDP_ENABLED", truthy)], || {
                let config = CaptureConfig::from_env().expect("config");
                assert!(
                    config.udp_capture_enabled,
                    "'{truthy}' must parse as UDP-enabled"
                );
            });
        }
        for falsy in ["false", "FALSE", "False", "0"] {
            with_capture_env(&[("FERRUM_MESH_CAPTURE_UDP_ENABLED", falsy)], || {
                let config = CaptureConfig::from_env().expect("config");
                assert!(
                    !config.udp_capture_enabled,
                    "'{falsy}' must parse as UDP-disabled"
                );
            });
        }
    }
}
