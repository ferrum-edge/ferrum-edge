# Ambient host-network UDP live-kernel gate (#3705 / ownership-safe cleanup #3804)

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
`unshare`/`ip`/`iptables`/`ip6tables` (including both save tools), `flock`, or
TPROXY primitives into hard failure.
Local ad-hoc runs without that flag may still print `SKIP:`.

## Isolation and ownership (#3804)

The hosted workflow runs the fixture inside a disposable outer network
namespace (`unshare --net`). Canonical Ferrum host-UDP objects therefore exist
only inside that sandbox; leaving `unshare` discards them. Pod-netns state
(table `33133`, priority `100`) is never touched.

`run.sh` itself is ownership-safe even for ad-hoc root runs outside that
boundary:

1. Root / tool / kernel / throwaway-netns preflight completes **before** any
   destructive cleanup trap is armed. Early `SKIP` and prerequisite failures
   leave host networking byte-for-byte unchanged.
2. Pre-existing canonical v4/v6 chains, `PREROUTING` jumps, priority-`101`
   rules, or table-`33135` local defaults cause an immediate refusal before
   mutation (unless the loud development override
   `FERRUM_HOST_UDP_LIVE_ALLOW_DESTRUCTIVE_ADOPT=1` is set — that path still
   refuses to claim or tear down the pre-existing objects).
3. A detected production `ferrum-edge` process is refused unless the run is
   already inside a disposable outer netns
   (`FERRUM_HOST_UDP_LIVE_IN_OUTER_NETNS=1`).
4. A namespace-scoped exclusive `flock` rejects a concurrent second fixture
   invocation before mutation.
5. An ownership ledger is written only after verified-empty acquisition under
   that lock. Cleanup removes only canonical objects while the ledger remains
   authoritative for this run; foreign/reconciled ownership fails closed
   (no snapshot-and-blind-delete).

Ordinary success, failure, `SKIP`, and handled-signal paths therefore cannot
tear down a live proxy's capture path.

### Explicit emergency destroy (development only)

If you intentionally need to wipe canonical Ferrum host-UDP objects in the
**current** network namespace, set
`FERRUM_HOST_UDP_LIVE_EMERGENCY_DESTROY_CANONICAL=1` and invoke `run.sh` as
root. That path is loud, never armed by ordinary exits, and is not used by the
hosted gate.

## Diagnostics

Bounded, redacted snapshots of `ip rule` / table `33135`, Ferrum mangle chains,
interface indexes, UDP bind state, and the ownership ledger are written under
`target/ambient-host-udp-live/` and uploaded by the workflow. Raw test output is
kept in temporary files outside the artifact tree and removed by cleanup.
