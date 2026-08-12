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
`unshare`/`mount`/`ip`/`iptables`/`ip6tables` (including both save tools),
`flock`, or TPROXY primitives into hard failure.
Local ad-hoc runs without that flag may still print `SKIP:`.

## Isolation and ownership (#3804)

The disposable outer network namespace is the ordinary ownership boundary.

Every normal root execution — hosted CI and ad-hoc alike — acquires a fixed
shared-filesystem exclusive lock, then runs the complete fixture inside a
**newly created** disposable outer network and mount namespaces (`unshare
--mount --net`). The runner mounts a fresh read-only sysfs instance there, so
production `/sys/class/net/<veth>` validation observes the disposable network
namespace rather than the caller's sysfs superblock. Before the live suites it
proves that view by creating and removing a disposable veth probe and observing
both changes in sysfs. Canonical Ferrum host-UDP objects therefore exist only
inside that sandbox and disappear when the owned netns lifetime ends. Ordinary
teardown never enumerates or deletes canonical host chains, jumps, rules, or
routes. Pre-existing canonical state in the caller's/host namespace remains
byte-for-byte untouched because normal execution never mutates that namespace.

Isolation is proven structurally before tests run: `/proc/self/ns/net` must
differ from the parent-captured identity and from `/proc/1/ns/net`. An
environment flag such as `FERRUM_HOST_UDP_LIVE_IN_OUTER_NETNS` is never accepted
as proof (operators can forge it on the host).

The hosted workflow also wraps execution in `unshare --net` explicitly. That
defense-in-depth layer composes with the runner's own outer netns; the trusted
relevance / `changes` job is untouched.

Contract details:

1. Root / tool / kernel / throwaway-netns preflight completes **before** any
   lock acquisition or outer-netns creation. Early `SKIP` and prerequisite
   failures leave host networking byte-for-byte unchanged.
2. A fixed exclusive `flock` at
   `/run/ferrum-edge-ambient-host-udp-live.lock` is acquired
   before the outer netns is created. A concurrent second invocation is
   rejected before mutation; the lock FD is held for the entire child run.
   `/run` is verified as a real, root-owned, non-group/world-writable directory,
   and a pre-existing lock path is rejected if it is a symlink, non-regular
   file, non-root-owned, or accessible to group/other users. New lock files are
   created under a `077` umask. Lock open/close uses safe Bash dynamic-FD
   redirection (no `eval`).
3. After the child exits, only temp files and the lock are released. Networking
   cleanup is the kernel discarding the owned outer netns — not per-object
   deletion in the parent/host namespace. Handled signals terminate and reap
   the child's complete process group before releasing the lock.
4. IPv4 and IPv6 live coverage remain symmetric inside the isolated environment.

### Explicit emergency destroy (development only)

If you intentionally need to wipe canonical Ferrum host-UDP objects in the
**current** network namespace, set
`FERRUM_HOST_UDP_LIVE_EMERGENCY_DESTROY_CANONICAL=1` and invoke `run.sh` as
root. That path is loud, separately gated, never armed by ordinary exits, and
is not used by the hosted gate. It does not weaken the normal isolation proof.

## Diagnostics

Bounded, redacted snapshots of `ip rule` / table `33135`, Ferrum mangle chains,
interface indexes, UDP bind state, and netns identities are written under
`target/ambient-host-udp-live/` and uploaded by the workflow. Raw test output is
kept in temporary files outside the artifact tree and removed by cleanup.
