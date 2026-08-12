# Ambient host-network UDP live-kernel gate (#3705)

Privileged hosted gate for the production Ambient host-network UDP capture
placement (`FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED=true` →
`ProxyHostUdpBackend`).

## What it proves

- Two independent workload netns / veth pairs
- IPv4 and IPv6 TPROXY delivery with original-destination recovery
- Kernel ingress-ifindex attribution and identical-tuple isolation by interface
- Transparent replies sourced from the captured destination
- Restart / reinstall and exact Ferrum-owned cleanup (table `33135`, priority
  `101`, chains `FERRUM_MESH_UDP_HOST` / `_GUARD_A` / `_GUARD_B`)
- Explicit negatives: source spoofing, missing/zero pktinfo, unenrolled /
  ambiguous interfaces, node-originated and inbound-to-pod traffic, fail-closed
  prerequisite / partial-install script contracts

## Skip-or-fail

`FERRUM_LIVE_TESTS_REQUIRED=1` (set by the workflow) converts missing root,
`unshare`/`ip`/`iptables`/`ip6tables` (including both save tools), or TPROXY
primitives into hard failure.
Local ad-hoc runs without that flag may still print `SKIP:`.

> **Run this on a disposable host.** `run.sh` installs an exit trap that
> unconditionally removes Ferrum-owned host UDP state in the caller's network
> namespace — the `FERRUM_MESH_UDP_HOST` / `_GUARD_A` / `_GUARD_B` mangle chains
> and their `PREROUTING` jumps, the priority-`101` v4/v6 `ip rule`s, and the
> `local` default routes in table `33135`. The trap runs on every exit, success
> included, and it does not check whether this fixture created that state. On a
> node where a real Ferrum ambient proxy is running the host-network UDP
> placement, an ad-hoc local run therefore tears that proxy's capture path down.
> The hosted gate is unaffected: it runs on an ephemeral runner with no Ferrum
> workload. Pod-netns state (table `33133`, priority `100`) is never touched.

## Diagnostics

Bounded, redacted snapshots of `ip rule` / table `33135`, Ferrum mangle chains,
interface indexes, and UDP bind state are written under
`target/ambient-host-udp-live/` and uploaded by the workflow. Raw test output is
kept in temporary files outside the artifact tree and removed by the exit trap.
