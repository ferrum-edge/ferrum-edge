# Node Agent Capture Contract

`FERRUM_MODE=node_agent` runs the per-node capture manager separately from mesh proxy mode. It owns only capture enrollment, eBPF map programming, and the narrow IPC surface described here; it does not merge policy evaluation or proxy dispatch into the node-agent process.

For the security posture of this mode (required Linux capabilities, mounts, seccomp / AppArmor profiles, NetworkPolicy, compromise containment), see [`docs/node_agent_security.md`](node_agent_security.md).

## Contract Surface

`CaptureContract` formalizes the node-agent to proxy boundary:

| Surface | Name / default | Purpose |
|---|---|---|
| Proxy mode | `FERRUM_NODE_AGENT_PROXY_MODE=local_pod` | Selects the capture topology. `local_pod` redirects to the co-located pod proxy. `node_waypoint` drives the sidecarless node-waypoint datapath: per-pod dual-family in-netns capture listeners, the GAP-2M socket-cookie bridge, the pod registry, and the direct-inbound pod-veth guard (see below). The remote `node-waypoint-ebpf-live` workflow gates IPv4 and IPv6 capture, secured node-to-node transport, SPIRE-backed identity, direct Pod-IP bypass checks, source workload IPv4 reuse, HBONE negative authentication probes, and SPIRE/NodeWaypoint restart recovery. |
| Admin listener | `FERRUM_NODE_AGENT_ADMIN_ENABLED=false` | Opts in to the read-only admin listener for node-agent metrics/health. When enabled, `FERRUM_ADMIN_HTTP_PORT` controls the port and the listener defaults to loopback unless `FERRUM_ADMIN_BIND_ADDRESS` or `FERRUM_ADMIN_ALLOWED_CIDRS` is set. |
| Outbound capture port | `15001` | The port written into the BPF capture config map and used by cgroup connect hooks when rewriting outbound sockets. |
| HBONE redirect port | `FERRUM_NODE_AGENT_HBONE_REDIRECT_PORT=15008` | The HBONE listener/redirect port carried in the same BPF config map for sidecarless topologies. Must match the mesh proxy HBONE listener (`15008` today). Node-agent startup automatically adds this port to outbound capture exclusions. |
| Unix socket | `/run/ferrum/node-agent.sock` | Reserved IPC path for future node-agent/proxy coordination. Phase 1 treats this as inert contract metadata; no socket is created yet. |
| BPF config map | `FERRUM_CAPTURE_CONFIG` | Singleton map keyed by `0`, containing outbound capture and HBONE redirect ports plus the NodeWaypoint inbound relay socket mark trusted by the pod-veth tc guard. |
| BPF pod maps | `FERRUM_POD_IPS`, `FERRUM_POD_IPS6` | IPv4/IPv6 pod IP to proxy-port and capture-lifecycle metadata for enrolled workloads. The tc guard treats these maps as the enrolled destination set and keeps pod-originated Ambient UDP closed until the producer-ready flag is set. |
| BPF node/probe maps | `FERRUM_NODE_IPS`, `FERRUM_NODE_IPS6`, `FERRUM_NODE_PROBE_PORTS`, `FERRUM_NODE_PROBE_PORTS6` | Explicit trusted kubelet probe source IPs plus enrolled pod probe ports allowed through the NodeWaypoint direct-inbound guard. Helm does not infer host-interface addresses; set `nodeAgent.trustedKubeletProbeSourceIps` only to known kubelet probe source IPs, such as a CNI bridge gateway address. The node-agent derives probe ports from Kubernetes HTTP/TCP/gRPC liveness, readiness, and startup probes. |
| BPF original destination maps | `FERRUM_ORIG_DST4`, `FERRUM_ORIG_DST6` | Socket-cookie keyed original destination records. The `connect4`/`connect6` hooks write them (stamped with the source pod's UID + SPIFFE hash from `FERRUM_WORKLOAD_IDENTITY`); the node-agent pins them at `/sys/fs/bpf/ferrum/orig_dst{4,6}`; the node-waypoint mesh-proxy's **orig-dst bridge** (`src/ebpf/orig_dst_bridge.rs`) mirrors each record into the `NodeWaypointIdentityResolver`. |
| BPF workload identity map | `FERRUM_WORKLOAD_IDENTITY` | Per-cgroup source workload identity (`{pod_uid, workload_spiffe_hash}`), keyed by `bpf_get_current_cgroup_id`. The node-agent writes one entry per enrolled pod cgroup; the connect hooks read it to stamp orig-dst records. Absent entry → connect hooks store the all-zero sentinel, which node-waypoint resolution treats as fail-closed. |
| BPF capture filters | `FERRUM_BYPASS_UIDS`, `FERRUM_CIDR_*`, `FERRUM_PORT_EXCLUDE` | UID, CIDR, and port exclusions applied before outbound rewrite. |

The eBPF connect programs read `FERRUM_CAPTURE_CONFIG` before rewriting to loopback. If the singleton config entry is absent, they fall back to ABI defaults so older loaders fail open to the historical `15001` behavior.

## Pod Lifecycle Events

The node-agent watches pods on the local node via kube-rs (`spec.nodeName={node_name}` field selector) and reacts to three Kubernetes event flavors. `Event::Apply` from the watcher conflates "added" and "modified", so the same code path handles initial enrollment and mid-life updates.

| Event | Source trigger | Node-agent action |
|---|---|---|
| Initial `Apply` for a previously-unseen pod | Pod creation | Resolve cgroup path, attach `connect4`/`connect6`/`getpeername4`/`getpeername6` programs, attach the host-side pod-veth tc classifier on ingress/egress, write `FERRUM_POD_IPS` / `FERRUM_POD_IPS6`, write `FERRUM_INCLUDE_PORTS` if the pod carries `includeOutboundPorts`. Counts toward `ferrum_node_agent_pods_enrolled_total`. |
| Subsequent `Apply` for an already-tracked pod | Pod metadata, label, or annotation update; status/condition change; container restart | Re-evaluate enrollment criteria (opt-in/opt-out labels and annotations), reconcile pod IP, **diff the parsed `includeOutboundPorts` policy** against the stashed baseline. Identical policy is a structural no-op (no BPF syscalls). A changed policy re-programs `FERRUM_INCLUDE_PORTS` for that pod's cgroup id; removed annotation drops the entry. Opt-in→opt-out flip triggers un-enrollment, opt-out→opt-in triggers enrollment. |
| `Delete` | Pod deletion | Detach BPF programs, remove `FERRUM_POD_IPS` / `FERRUM_POD_IPS6` and `FERRUM_INCLUDE_PORTS` entries. Counts toward `ferrum_node_agent_pods_unenrolled_total`. |

Mid-life update guarantees:

- **Diff-skip:** comparison is against the parsed, sorted, deduplicated `IncludePortsPolicy`, not the raw annotation string. Reordering ports in the annotation is a no-op. Modified events from unrelated pod activity (image pulls, status updates) cost only the diff compare.
- **Long-lived flows are unaffected:** the BPF gate runs on `connect(2)`, so a re-applied policy applies only to new outbound connections. Already-established TCP flows continue using the redirect chosen at their original connect — explicit application restart is required to force them through the new policy.
- **Best-effort:** annotation parse errors and BPF map write errors keep the previous policy in place rather than silently widening capture. They are recorded in `ferrum_node_agent_pod_annotation_updates_failed_total`. Cgroup-id-unavailable retries (the Pod object reached the watcher before kubelet finished creating the cgroup) are intentionally not counted there because they are routinely observed during early pod startup and are retried on the next Apply event.

## Metrics

When node-agent mode starts its admin listener, `/metrics` includes:

| Metric | Meaning |
|---|---|
| `ferrum_node_agent_pods_enrolled_total` | Pods successfully enrolled for capture. |
| `ferrum_node_agent_pods_unenrolled_total` | Pods unenrolled due to deletion, label changes, or shutdown. |
| `ferrum_node_agent_attach_errors_total` | BPF attachment or map update failures. |
| `ferrum_node_agent_pod_annotation_updates_applied_total` | Mid-life `includeOutboundPorts` annotation changes successfully re-applied to the BPF map (excludes initial enrollment, excludes diff-skipped Modified events). |
| `ferrum_node_agent_pod_annotation_updates_failed_total` | Mid-life `includeOutboundPorts` annotation changes that failed to re-apply (annotation parse error or BPF map write error). The pod retains its previous policy. Cgroup-id-unavailable retries (Pod object reached the watcher before kubelet finished creating the cgroup) are not counted here — they are retried on the next Apply event. |
| `ferrum_node_agent_capture_state{state}` | Gauge. Exactly one state is `1`: `starting`, `ready`, `unavailable`, `partially_attached`, `identity_bridge_unavailable`, or `node_global_fallback`. Readiness is only reported after startup BPF maps/programs are loaded and, in NodeWaypoint mode, the SOCK_OPS identity bridge is attached. |
| `ferrum_mesh_node_topology_degraded{reason}` | Gauge. `1` with `reason` ∈ {`kernel_too_old`,`cgroup_v1`,`bpffs_missing`,`ebpf_feature_disabled`,`capture_mode_not_ebpf`,`capture_unavailable`,`node_waypoint_sock_ops_unavailable`} when startup cannot provide the requested eBPF topology. `0` with `reason="none"` when the eBPF capture path is nominal. Cardinality is bounded per node (a single series at a time). |

## eBPF build and capture (how to build the capture image)

The capture programs live in the `ebpf/` Cargo workspace (`ferrum-ebpf`, a
`#![no_std]` crate) and share `#[repr(C)]` ABI types with userspace via
`ferrum-ebpf-common`. The userspace aya loader (`src/ebpf/loader.rs`) and every
BPF map read are gated behind `#[cfg(all(feature = "ebpf", target_os = "linux"))]`.

> **What the published images ship.** Two image variants are published per
> release tag:
>
> - **Default (mock).** `ferrumedge/ferrum-edge:<tag>` /
>   `ghcr.io/ferrum-edge/ferrum-edge:<tag>` (multi-platform: linux/amd64,
>   linux/arm64, plus the macOS/Windows binaries) are built from
>   `Dockerfile.release` with `--features cloud-secrets`. That Dockerfile has
>   **no `ebpf-builder` stage, no compiled ELF, and does not set
>   `FERRUM_NODE_AGENT_BPF_ELF_PATH`** — so this node-agent always selects the
>   mock backend. In `FERRUM_MODE=node_agent` with
>   `FERRUM_MESH_CAPTURE_MODE=ebpf`, startup refuses that backend, sets
>   `ferrum_mesh_node_topology_degraded{reason="ebpf_feature_disabled"}=1` and
>   `ferrum_node_agent_capture_state{state="unavailable"}=1`, then exits. The
>   default binary can still run non-capture modes, but it cannot report Ready
>   for an enabled eBPF node-agent topology.
> - **`-ebpf` (real capture, Linux-only).**
>   `ferrumedge/ferrum-edge:<tag>-ebpf` /
>   `ghcr.io/ferrum-edge/ferrum-edge:<tag>-ebpf` are built **from source** by
>   the release pipeline's `docker-ebpf` job using the root `Dockerfile` with
>   `--build-arg FEATURES=cloud-secrets,ebpf`, which compiles in the aya loader
>   **and** embeds the compiled `ferrum-ebpf` BPF ELF (see "Building the capture
>   image" below). It is **Linux-only** (linux/amd64 + linux/arm64; the aya
>   kernel loader compiles only on Linux) and requires a node kernel **≥ 5.7**
>   with cgroup v2 and the capabilities in
>   [`docs/node_agent_security.md`](node_agent_security.md): on kernel ≥ 5.8
>   `CAP_BPF`/`CAP_NET_ADMIN`/`CAP_PERFMON`; on the 5.7.x window `CAP_SYS_ADMIN`
>   (+ `CAP_NET_ADMIN`), because `CAP_BPF`/`CAP_PERFMON` did not exist until 5.8.
>   `node_waypoint` mode additionally requires `CAP_SYS_ADMIN` on all supported
>   kernels because enrollment enters pod network namespaces with `setns()` to
>   resolve host-side veth peers before attaching pod-veth tc classifiers.
>   On a node that fails the kernel/cgroup/bpffs probe the `-ebpf` pod does **not**
>   silently degrade to the mock backend: `run()` hands off to `handle_fallback`,
>   whose default `FERRUM_NODE_AGENT_FALLBACK_MODE=fail` returns an error and the
>   pod **exits** (crash-loops). The only continuing fallback is the explicit
>   `FERRUM_NODE_AGENT_FALLBACK_MODE=iptables`, which switches to host iptables
>   capture (not the mock) and requires a runtime image with `/bin/sh` +
>   `iptables`/`ip6tables` — see [Kernel fallback](#kernel-fallback). (The mock
>   backend is only ever selected by a build *without* `--features ebpf`, e.g. the
>   default image, never by the `-ebpf` image on a bad kernel.) **Release
>   gating:** the default `:<tag>` image and the per-platform binary assets
>   publish **independently** of the `-ebpf` variant — a variant build failure
>   never blocks them (they flow through the `docker` / `docker-manifest` jobs).
>   The **GitHub Release page**, however, is now gated on the `-ebpf` manifest:
>   `create-release` `needs: docker-ebpf-manifest`, because the release notes
>   advertise the `-ebpf` tags and must not publish until those manifests exist.
>   So if the default image + binaries push but the `-ebpf` build/manifest fails,
>   you will see the core artifacts in the registry with **no GitHub Release**;
>   re-run the failed `docker-ebpf` / `docker-ebpf-manifest` jobs (and then
>   `create-release`) from
>   [`.github/workflows/release.yml`](../.github/workflows/release.yml) to finish
>   the release. Conversely, `docker-ebpf-manifest` itself `needs:` the core
>   release path, so the `-ebpf` tags are never published for a release whose
>   core artifacts failed.

**Building the capture image.** The compiled BPF ELF and the `--features ebpf`
binary are produced by the root `Dockerfile`'s `docker build .`, and published as
the `-ebpf` release variant by the `docker-ebpf` job in
[`.github/workflows/release.yml`](../.github/workflows/release.yml):

- The `ebpf-builder` stage installs nightly + `rust-src` + `bpf-linker` and runs
  `cargo +nightly build -p ferrum-ebpf --target bpfel-unknown-none -Z build-std=core --release`
  (the `ebpf/rust-toolchain.toml` pins the nightly). The ELF is COPY'd into the
  runtime image at `/app/bpf/ferrum-ebpf`, and `FERRUM_NODE_AGENT_BPF_ELF_PATH`
  defaults to that path.
- The main binary must be built with `--build-arg FEATURES=cloud-secrets,ebpf`
  to compile in the aya loader. A root-`Dockerfile` image built with the
  **default** `FEATURES=cloud-secrets` (no `ebpf`) still builds and runs and
  ships the ELF, but — lacking the aya loader — would otherwise select the same
  mock backend as the release image. Enabled eBPF node-agent mode rejects that
  backend before readiness, sets the degraded/capture-state metrics, and exits
  instead of silently reporting Ready.

**Non-eBPF builds stay working.** Local `cargo build`/`cargo test` on any
platform compile the mock backend and the no-op orig-dst bridge stub. The
`ferrum-ebpf` ELF build and the Linux aya code paths require the `bpf-linker`
toolchain and a Linux target, so they are exercised by the `ebpf-builder`
Docker stage / Linux CI, not by a macOS or default `cargo build`.

### Orig-dst → proxy identity bridge (node-waypoint)

In node-waypoint topology one mesh-proxy accepts traffic for many pods, so the
proxy must recover the *source* pod identity from each accepted socket. The
pipeline:

1. The `connect4`/`connect6` cgroup hooks run in the **source pod's** cgroup.
   They look up `FERRUM_WORKLOAD_IDENTITY` by `bpf_get_current_cgroup_id` and
   stamp the resulting `{pod_uid, workload_spiffe_hash}` onto the
   `FERRUM_ORIG_DST4`/`FERRUM_ORIG_DST6` record they write (keyed by socket
   cookie), then redirect the connection. The node-agent populates
   `FERRUM_WORKLOAD_IDENTITY` per enrolled pod cgroup
   (`update_workload_identity`).
2. The node-agent pins the orig-dst maps at `/sys/fs/bpf/ferrum/orig_dst{4,6}`.
3. The node-waypoint mesh-proxy runs the **orig-dst bridge**
   (`src/ebpf/orig_dst_bridge.rs`): it opens the pinned maps by path and
   mirrors each cookie→identity record into the `NodeWaypointIdentityResolver`
   (`record_orig_dst4`/`record_orig_dst6`).

> **Caveat — capture live-gated; transport still Experimental.** The
> connect-side vs accept-side cookie mismatch — the bridge mirrors records keyed
> by the **connect-side** socket cookie, but the proxy accept path resolves by
> the **accepted** socket's cookie — is now bridged by the kernel `sock_ops`
> program (GAP-2M): at active-established it re-keys the IPv4 or IPv6 record by
> `(netns cookie, connection tuple)`, and at passive-established it re-stamps it
> under the accept-side cookie, so `resolve_stream` matches the mirrored
> record. Pod-UID resolution (`identities_by_pod_uid`) is also wired — the
> resolver lazily enrolls `pod_uid`→identity by hash-joining the slice's
> `workload_spiffe_hash`→SPIFFE index against the eBPF-stamped record. If two
> SPIFFE IDs collide on that truncated hash, the proxy marks the hash unusable
> and fails closed instead of picking either identity. The IPv4 and IPv6
> connect→capture→accept datapaths are gated by the Docker/kind
> `node-waypoint-ebpf-live` GitHub Actions workflow, which runs on a two-worker
> Linux cluster and collects BPF link/map evidence. On any
> tuple/byte-order/enrollment miss no accept-side record is written and the
> accept path resolves no identity (fail-closed, never misattributed).

The bridge polls (the orig-dst maps are LRU hash maps, not ringbufs), ages out
cookies the kernel evicted, retries with backoff if the mesh-proxy starts
before the node-agent pins the maps, and re-opens on a pin-inode change
(node-agent restart). Without a node-agent / eBPF build, the bridge logs once
that no capture runs and returns — the resolver stays empty and every
node-waypoint accept fails closed.

> **Remote verification.** The userspace bridge, BPF map declarations, identity
> stamping, ABI types, Docker build wiring, and non-kernel tests are covered by
> the regular suite. End-to-end kernel verification runs in the
> `node-waypoint-ebpf-live` workflow: it builds the `-ebpf` image, loads it into
> a disposable dual-stack kind cluster, validates BPF attachments/maps, and
> exercises same-node and cross-node policy-scoped traffic.

## Pod registry for in-netns capture (node-waypoint TCP + Ambient UDP)

In node-waypoint topology the mesh proxy's in-pod-netns outbound capture
listeners (always on for NodeWaypoint) accept the captured pod-loopback
`127.0.0.1:<outbound port>` connections *inside* each enrolled pod's network
namespace. To let the proxy find those pods, the node-agent publishes a per-pod
registry directory — the same
"pinned path is the node-agent↔mesh-proxy IPC surface" pattern as the orig-dst
maps:

| Surface | Name / default | Format |
|---|---|---|
| Pod registry dir | `FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR` (default `/run/ferrum/node-waypoint-pods`) | One file per enrolled pod. File **name** = pod UID; file **contents** = line 1 pod cgroup path, then optional `ipv4=<pod-ip>` / `ipv6=<pod-ip>` lines from Kubernetes `status.podIPs`. |

Helm sets `nodeAgent.podRegistryDir` to that default and mounts it as the same
writable hostPath in both DaemonSets for NodeWaypoint or an Ambient eBPF
node-agent, including the UDP-disabled stale-rule cleanup posture. If operators
override the path,
both processes must see the same host directory; a container-local directory
lets both pods report Ready while no in-netns capture listener is attached for
workloads. The chart rejects incomplete NodeWaypoint topologies at render time:
ambient `FERRUM_MESH_TOPOLOGY=node_waypoint` requires
`nodeAgent.enabled=true`, `nodeAgent.captureMode=ebpf`, and
`nodeAgent.proxyMode=node_waypoint`, and node-agent `proxyMode=node_waypoint`
requires the matching ambient proxy.

For NodeWaypoint, the ambient proxy also needs host access normally associated
with the node-agent: `hostPID: true`, a read-only host cgroup mount, a read-only
host bpffs mount, and `BPF`/`PERFMON`/`SYS_ADMIN`/`SYS_PTRACE` capabilities.
The proxy uses the cgroup mount plus host `/proc` to resolve each registered
pod's live network namespace, `SYS_PTRACE` for the kernel's
`ptrace_may_access` checks on `/proc/{pid}/ns/net` across workload UIDs,
`SYS_ADMIN` to `setns(CLONE_NEWNET)` and bind the pod-loopback listener, and
bpffs/BPF access to open the node-agent-pinned orig-dst and SOCK_OPS maps. The
chart adds those settings only when
`nodeAgent.proxyMode=node_waypoint` and the ambient topology is
`node_waypoint`.

The node-agent **writes** a pod's registry file on enrollment and **removes**
it on teardown. The mesh proxy's `NetnsCaptureManager` polls this directory and
reconciles IPv4 and IPv6 in-netns listeners per pod netns (opening on add,
closing on removal). The family-specific `ipv4=` and `ipv6=` lines are used as
dynamic source-IP overrides for the matching listener family so IPv6 captured
traffic is attributed to the pod's IPv6 address instead of reusing the IPv4
override or the pod-loopback peer.

### Also consumed by the Ambient UDP capture producer (#2013)

The **same** registry is published for every **Ambient** deployment. The enabled
producer consumes it when `FERRUM_MESH_CAPTURE_UDP_ENABLED=true`; when UDP is
disabled, the stale-rule cleanup manager still needs current pod netns entries
to repair an enabled-to-disabled rollout. The node-agent publish gate is
`should_publish_registry = node_waypoint_in_netns || ambient_topology`, while
the BPF UDP readiness guard remains separately gated on both the UDP flag and
`FERRUM_MESH_TOPOLOGY=ambient`. Setting the shared UDP flag on a topology that
starts no per-pod producer therefore does not arm a guard that could never
become ready.
The UDP term is deliberately **not** anded with `outbound_capture_enabled`: the
Ambient UDP producer binds its own `FERRUM_MESH_CAPTURE_UDP_PORT` inside each
pod netns and never uses the TCP `FERRUM_MESH_OUTBOUND_LISTEN_ADDR` listener, so
a port-0 outbound listener (which disables the TCP connect-redirect path) must
not suppress registry publication — that would leave the producer polling an
empty directory while pod UDP egress bypasses capture. Publishing for the
Ambient-UDP case does **not** flip the NodeWaypoint ipv6-outbound-deny /
connect4-deferral posture (that stays gated on `node_waypoint_in_netns`) — it
only makes the per-pod `uid → cgroup` registry available so the Ambient mesh
proxy's producer or disabled cleanup manager (`src/proxy/netns_udp_capture.rs`)
can discover enrolled pods. For each pod the producer enters the pod netns
(`setns(CLONE_NEWNET)` on a dedicated thread), installs a dedicated fail-closed
OUTPUT guard, then binds the transparent capture socket and installs the UDP
TPROXY rules while that guard remains active. The guard mirrors the operator's
exact outbound include/exclude/family scope and uses alternating chains, so a
bind collision, setup failure, or guarded retry cannot reopen plaintext egress.
It is removed only after the bound socket has been adopted and the full
capture ruleset is live. A failed attempt transfers a stable-netns guard cleanup
handle to the manager, so registry removal or shutdown still removes the guard
even if no active producer was ever created; transient cleanup failures retain that
handle for the next reconcile, while shutdown runs retained cleanup inside its bounded
teardown set. Guard release treats xtables resource errors as failures, removes every
duplicate jump, and always probes Ferrum-owned IPv6 guard chains left by an
earlier IPv6-enabled run even when IPv6 capture is now disabled. The reply sockets
are created in the same pod netns.

Enrollment is fail-closed before the producer's first poll. The node-agent writes
each pod's `FERRUM_POD_IPS` / `FERRUM_POD_IPS6` entry with UDP capture enabled but
not ready before it publishes the registry entry. The host-veth tc classifier
drops pod-originated UDP in that state. After the producer's in-netns guard,
socket, and complete TPROXY ruleset are live, it publishes
`<registry_dir>/.udp-ready/<pod_uid>`; the node-agent observes that marker and
opens the BPF gate. A stale marker is removed before re-enrollment or a guarded
producer retry, and marker/map updates are idempotent. Therefore the polling
interval can delay UDP readiness, but it cannot create a plaintext bypass
window. On producer stop, readiness is removed first and the producer waits for
`<registry_dir>/.udp-not-ready/<pod_uid>`, which the node-agent writes only after
the BPF ready bit is cleared or pod unenrollment has verifiably removed the BPF
gate. In an explicitly disabled rollout, the new node-agent first re-applies the
UDP-disabled pod-map flags from live pod state and then publishes the same ack;
it never trusts a persisted ack from an older process generation. A failed map
update/removal or classifier detach keeps capture degraded and withholds that
acknowledgement; after a bounded wait
the producer retains its in-netns fail-closed guard while releasing the producer
tasks/netns handle instead of tearing down into plaintext. The live
bind-collision/source-capture verification remains part of #2038.

The Ambient UDP producer needs the same host access the NodeWaypoint in-netns
listener needs — the read-only host cgroup mount + host `/proc` to resolve pod
netns and `SYS_ADMIN`/`SYS_PTRACE` for `setns(CLONE_NEWNET)` — plus **`NET_ADMIN`**
to install the in-netns `iptables`/`ip` TPROXY rules and to bind the
`IP_TRANSPARENT` capture and reply sockets, and `iptables`/`ip6tables`/`ip`/`sh`
present in the proxy image. The proxy's own (host) network namespace is never
given UDP TPROXY rules — the host-netns iptables fallback emits none (there is no
host-netns-safe direction discriminator); the rules live **only** inside each pod
netns.

**Fail-closed startup enforcement.** In-netns listener startup is asynchronous,
so the mesh proxy may not yet have accepted the registry entry when pod
enrollment returns. The node-agent still attaches the outbound-redirect programs
(`connect4` and `connect6`) during enrollment, before the pod is marked
enrolled, so newly started workloads cannot open direct egress connections that
bypass `mesh_authz`. Until the proxy opens the pod-loopback listener for an
address family, captured connections for that family may be refused, but they
fail closed instead of bypassing policy. The inbound `getpeername4`/
`getpeername6` programs are also attached during enrollment.

For destination-side bypass protection, the same enrollment writes the pod's
IPv4 and IPv6 addresses into `FERRUM_POD_IPS` / `FERRUM_POD_IPS6` and attaches
`ferrum_tc_inbound` to the host-side veth on ingress/egress. In local-pod mode
the BPF config carries a zero inbound mark and this guard passes traffic through.
In NodeWaypoint mode, TCP packets whose destination is an enrolled pod IP are
dropped unless they both come from an explicitly configured local-node source in
`FERRUM_NODE_IPS` / `FERRUM_NODE_IPS6` and carry the inbound relay auth mark from
`FERRUM_CAPTURE_CONFIG`; the destination HBONE relay sets that mark with
`SO_MARK` before dialing the local backend pod. The source-IP check prevents a
workload that can forge ordinary Linux socket marks from using the mark alone as
a direct-pod bypass. Direct UDP/DTLS to enrolled pod IPs fails closed because no
authorized UDP relay path exists yet, except DNS responses from source port 53
back to high pod-originated client ports (`>=32768`); ARP/ICMP and other control
traffic remains pass-through. Packets sourced from explicitly configured trusted
kubelet probe source IPs in `FERRUM_NODE_IPS` / `FERRUM_NODE_IPS6` can also reach
enrolled pod TCP probe ports without the relay mark when those ports are derived
into `FERRUM_NODE_PROBE_PORTS` / `FERRUM_NODE_PROBE_PORTS6` from the pod's
HTTP/TCP/gRPC liveness, readiness, or startup probe. Keep
`FERRUM_NODE_AGENT_NODE_IPS` limited to source addresses that are required for
the host-network relay and kubelet probes; other host traffic still needs the
trusted relay mark or follows the UDP/extension-header fail-closed behavior.

Because the relay dials backend pods from a node-local source address, at least
one trusted node source IP (`FERRUM_NODE_AGENT_NODE_IP` /
`FERRUM_NODE_AGENT_NODE_IPS`, surfaced as `FERRUM_NODE_IPS` / `FERRUM_NODE_IPS6`)
is **required** in NodeWaypoint mode: with the source-bound guard, an empty
node-source set would drop the relay's own SYNs and break all inbound to enrolled
pods. The node-agent therefore **fails closed** (capture reported unavailable)
rather than silently black-holing the data path when no node source IP is
configured. The address is CNI-specific and is not auto-detected — it is the host
source the kernel uses to reach local pods (for example the node's pod-CIDR
gateway, which may differ from the node's `status.hostIP`), so set it explicitly
via `nodeAgent.trustedKubeletProbeSourceIps`.

NodeWaypoint adds `::/0` to the capture include set so IPv6 destinations reach
`connect6`; the legacy `ipv6_outbound_deny` flag remains clear in the normal
dual-family path. Excluded v6 (CIDR/port excludes) still flows. The proxy writes
`<registry_dir>/.ready/<pod_uid>` for the historical IPv4 readiness marker,
`<registry_dir>/.ready4/<pod_uid>` for IPv4, and
`<registry_dir>/.ready6/<pod_uid>` for IPv6; these dotdirs are skipped by the
pod-discovery scan.

This is Linux-only and, like the rest of the in-netns datapath, is gated by the
remote `node-waypoint-ebpf-live` workflow because it needs a live multi-pod
node.

## Kernel Fallback

The node agent probes the kernel once at startup (see `KernelProbeResult::supports_ebpf`):

1. Linux kernel version >= 5.7 (required for cgroup_sockaddr BPF programs).
2. cgroup v2 mounted at `FERRUM_NODE_AGENT_CGROUP_ROOT` (default `/sys/fs/cgroup`).
3. bpffs mounted at `FERRUM_NODE_AGENT_BPF_FS_PATH` (default `/sys/fs/bpf`).

If any prerequisite is missing, the node agent fails fast by default. It logs the first-failing prerequisite as `degradation_reason`, sets `ferrum_mesh_node_topology_degraded{reason="<...>"}` to `1`, sets `ferrum_node_agent_capture_state{state="unavailable"}` to `1`, and exits. `FERRUM_NODE_AGENT_FALLBACK_MODE` controls the behaviour:

| Value | Behaviour |
|---|---|
| `fail` (default) | Refuse to start, surface the kernel deficiency in the error log, and exit. This matches the published distroless image, which does not include `/bin/sh`, `iptables`, or `ip6tables`. |
| `iptables` | Apply host iptables capture rules and continue serving. This requires a custom runtime image that includes `/bin/sh`, `iptables`, and `ip6tables` when IPv6 capture is enabled. The gauge records the reason; pod-level eBPF enrollment is skipped. Existing pods that were enrolled before degradation keep working until the next reconcile; new pods rely on the iptables capture path. |

Suggested remediations by reason label:

| `reason` | Remediation |
|---|---|
| `kernel_too_old` | Upgrade the node to a kernel >= 5.7. Most modern distributions (RHEL 9 / Ubuntu 22.04 / Debian 12 / Amazon Linux 2023) already satisfy this. |
| `cgroup_v1` | Mount the unified cgroup v2 hierarchy (`systemd.unified_cgroup_hierarchy=1` on systemd hosts). cgroup_sockaddr BPF programs require cgroup v2 and cannot attach to the v1 hierarchy. |
| `bpffs_missing` | Mount `bpffs` at the configured `FERRUM_NODE_AGENT_BPF_FS_PATH`: `mount -t bpf bpffs /sys/fs/bpf`. The DaemonSet manifest in `charts/ferrum-mesh/` mounts this automatically when configured. |

### Mixed-kernel clusters

In a cluster with heterogeneous kernels, the recommended pattern is:

1. Deploy the node-agent DaemonSet to every node with the default `FERRUM_NODE_AGENT_FALLBACK_MODE=fail`; degraded nodes stay NotReady and the startup error identifies the remediation reason.
2. If you intentionally want degraded nodes to keep routing while kernels are upgraded, run a custom node-agent image that includes `/bin/sh`, `iptables`, and `ip6tables`, then set `FERRUM_NODE_AGENT_FALLBACK_MODE=iptables` for those nodes.
3. Configure the admission webhook (`FERRUM_MODE=injector`) to inject iptables init containers for pods scheduled on degraded nodes. The injector decides this from a Helm-templated `NodeSelector` driven by your node labels (e.g., `ferrum.io/capture-mode=iptables`).

The mesh control plane is not changed by node-level degradation: slice apply, `mesh_authz`, `mesh_workload_metrics`, and HBONE all continue to function as ambient. Only the per-pod capture mechanism on the affected node changes.

The node agent starts the read-only admin HTTP listener on `FERRUM_ADMIN_HTTP_PORT` unless that port is set to `0`. Node-agent mode does not start an HTTPS admin listener yet, even when `FERRUM_ADMIN_HTTPS_PORT` is set.

The Helm chart sets `nodeAgent.admin.port` to `19090` by default. The binary default remains `9000`, but the chart uses a different host-network port so an ambient NodeWaypoint proxy and node-agent can run on the same node without an admin listener collision.

`/metrics` is unauthenticated, matching the rest of Ferrum's Prometheus surface. To prevent an opt-in to `FERRUM_NODE_AGENT_ADMIN_ENABLED=true` from accidentally exposing unauthenticated `/metrics` and `/health` to the network, the node-agent admin listener defaults to loopback (`127.0.0.1`) when **none** of the following operator signals are configured:

- `FERRUM_ADMIN_BIND_ADDRESS` is set explicitly (any value, including `0.0.0.0` if intentional), or
- `FERRUM_ADMIN_ALLOWED_CIDRS` is set to a non-empty allowlist.

`FERRUM_ADMIN_JWT_SECRET` does not affect the bind address because `/metrics` and `/health` remain unauthenticated. The two signals resolve as follows: an explicit `FERRUM_ADMIN_BIND_ADDRESS` is honored verbatim; an `FERRUM_ADMIN_ALLOWED_CIDRS` allowlist with no explicit bind binds the listener to `0.0.0.0` (restricted by that allowlist) so cluster scraping can reach `/metrics` — because the bind now defaults to loopback, the allowlist alone would otherwise leave the listener unreachable. When neither signal is set, the listener stays on `127.0.0.1` and the gateway emits a `warn!` at startup pointing at the two opt-ins. For node-agent deployments scraped over the cluster network, prefer the `FERRUM_ADMIN_ALLOWED_CIDRS` allowlist (which must include the scrape source ranges) or front the listener with a local sidecar scraper bound to loopback.

> **Helm chart users:** the allowlist-only `0.0.0.0` behavior above applies to the **raw env** contract. The `charts/ferrum-mesh` node-agent DaemonSet always renders `FERRUM_ADMIN_BIND_ADDRESS` from `nodeAgent.admin.bindAddress` (default `127.0.0.1`) whenever node-agent admin is enabled, so the bind is always an explicit signal and the allowlist-only branch never engages through the chart. To expose `/metrics` for cluster scraping via Helm, set **`nodeAgent.admin.bindAddress=0.0.0.0`** (and `nodeAgent.admin.allowedCidrs` to the scrape source ranges); setting only the allowlist leaves a loopback listener and scraping fails.

When ambient NodeWaypoint and the node agent run on the same host-network nodes, their admin listeners must use distinct `FERRUM_ADMIN_HTTP_PORT` values or one listener must be disabled with port `0`. The Helm chart rejects equal host-network admin ports, and the binary also treats an enabled admin-listener bind failure as fatal startup rather than continuing to report ready.

## CNI plugin install (optional)

The node-agent's default enrollment path is the kube-rs pod watcher: it polls the Kubernetes API for pods scheduled to its node and reconciles BPF attachment from the resulting label/annotation snapshots. That works but races kubelet — a freshly-scheduled pod may complete its CNI sandbox setup, attach a network namespace, and start sending traffic *before* the watcher has seen the `Apply` event. During that window outbound traffic is not yet routed through Ferrum's eBPF redirect.

The optional CNI-style install closes that window. A small `ferrum-cni` binary, dropped into the host's `/opt/cni/bin/` directory and chained behind the cluster's primary CNI (Calico, Cilium, etc.), forwards each ADD/DEL/CHECK invocation from kubelet to the long-lived node-agent over a Unix domain socket. On ADD, the node-agent fetches the pod from the Kubernetes API by namespace/name so it can evaluate labels and annotations immediately; the kube-rs watcher still runs afterward as the source of truth for reconciliation.

### Architecture

```
                            ┌──────────────────────────────────────────────┐
                            │                  worker node                 │
                            │                                              │
                            │  ┌─────────┐    /opt/cni/bin/ferrum-cni      │
                            │  │ kubelet │ ───────────────────────┐        │
                            │  └─────────┘                        │        │
                            │       │ ADD/DEL/CHECK               ▼        │
                            │       ▼ (stdin JSON +       ┌──────────────┐ │
                            │  /etc/cni/net.d/             │  ferrum-cni  │ │
                            │  ...-ferrum.conflist         │   (binary)   │ │
                            │  (chained behind primary)    └──────┬───────┘ │
                            │                                     │         │
                            │                              UDS    │ length- │
                            │                              ┌──────▼──────┐  │
                            │                              │ /var/run/   │  │
                            │                              │ ferrum/     │  │
                            │                              │ node-agent- │  │
                            │                              │ cni.sock    │  │
                            │                              └──────┬──────┘  │
                            │                                     │         │
                            │                          ┌──────────▼──────┐  │
                            │                          │  node-agent     │  │
                            │      (kube-rs            │  (DaemonSet)    │  │
                            │       watcher) ────────▶ │                 │  │
                            │       fallback           │  ───── eBPF ──▶ │  │
                            │                          │  redirect maps  │  │
                            │                          └─────────────────┘  │
                            └──────────────────────────────────────────────┘
```

The CNI plugin and the kube-rs watcher feed the same enrollment path. They are deliberately not mutually exclusive: even with the CNI plugin installed, the watcher continues to run and reconcile, so the CNI hook is an **optimization** rather than a hard dependency.

### Install steps

The Helm chart at `charts/ferrum-mesh/` ships an opt-in CNI installer init container, gated by `nodeAgent.cni.enabled`. When enabled:

1. The DaemonSet pod's init container runs `/app/ferrum-cni install`, which copies the binary into the host's `/opt/cni/bin/` (host-path mount).
2. The installer reads the existing primary CNI config matching `nodeAgent.cni.chainedWith`, preserves its plugin fields/IPAM, appends Ferrum as a meta-plugin, and writes the generated `*-ferrum.conflist` into `/etc/cni/net.d/`.
3. The node-agent container mounts `/var/run/ferrum/` so both the binary and the daemon share the UDS path.
4. Set `FERRUM_NODE_AGENT_CNI_ENABLED=true` (the chart sets this when `nodeAgent.cni.enabled=true`).

Manual install (no Helm): copy `ferrum-cni` to `/opt/cni/bin/` on every node, write a chained `.conflist` in `/etc/cni/net.d/` that preserves the primary CNI plugin/IPAM and appends Ferrum, ensure `/var/run/ferrum/` is writable, set `FERRUM_NODE_AGENT_CNI_ENABLED=true`. The default Unix socket path is `/var/run/ferrum/node-agent-cni.sock` (override via `FERRUM_NODE_AGENT_CNI_SOCKET_PATH`).

The listener holds a sibling `<socket>.lock` advisory lock for its complete
lifetime. A second live node-agent generation refuses to replace the active
owner and continues with watcher reconciliation; after a crash, the kernel
releases the lock and the next generation removes the stale socket before
publishing. A short fail-closed connect probe also preserves a live socket from
an older Ferrum version that predates the lock. Publication retains the
socket's device/inode identity, and
shutdown unlinks the well-known path only when it still names that identity,
so a draining old generation cannot remove an explicitly coordinated
replacement.

### Fallback semantics

- **Default disabled.** `nodeAgent.cni.enabled=false` (chart) / `FERRUM_NODE_AGENT_CNI_ENABLED=false` (env) keeps the kube-rs watcher as the sole enrollment path. Existing operators upgrade with zero behavior change.
- **Enabled but UDS unreachable.** If the listener fails to bind (permission error on the parent dir or another live generation holds the ownership lock), the node-agent logs `error!` and continues running with the watcher path active. Stale socket files from crashed owners are recovered only after the new process acquires that lock. The CNI binary on the host will then fail every kubelet invocation with `IpcFailed`, and kubelet will eventually mark the pod creation as failed — at which point the operator must either fix the UDS or roll back the chained CNI config. The watcher path will still enroll already-scheduled pods.
- **CNI plugin installed but node-agent not running.** Same effect as above: kubelet sees a CNI error and may delay sandbox setup. The watcher path is irrelevant here because the node-agent process is absent.
- **CNI plugin enabled, node-agent running, watcher disabled.** Not a supported configuration. The watcher is the source of truth for enrollment; the CNI hook only acknowledges sandbox-setup events to close the race window.

### Chained CNI compatibility

`ferrum-cni` is a *meta-plugin* in CNI parlance — it doesn't allocate IPs or interfaces. It must be chained **after** a primary CNI that does (Calico, Cilium, Flannel, AWS VPC CNI, etc.). The chart's `nodeAgent.cni.chainedWith` value selects the existing primary config to copy before appending Ferrum. Verify the generated config:

```bash
$ cat /etc/cni/net.d/00-ferrum.conflist
{
  "cniVersion": "0.4.0",
  "name": "calico",
  "plugins": [
    { "type": "calico", ... },
    { "type": "ferrum-cni",
      "ferrum": { "socketPath": "/var/run/ferrum/node-agent-cni.sock" } }
  ]
}
```

The generated `name` is preserved from the matched primary CNI config, so it will usually be the primary network name rather than a Ferrum-specific constant.

The chart writes the file at a numeric prefix (`00-`) so kubelet selects the generated chain before a typical `10-...` primary config file. Inside the generated file, the primary plugin still runs before `ferrum-cni`. Operators with custom primary prefixes should choose a generated filename that sorts before the runtime-selected primary config.

### Observability

`/metrics` exposes `ferrum_node_agent_cni_calls_total{verb,outcome}` with closed labels (`verb ∈ {add,del,check}`, `outcome ∈ {success,rejected,error}`). Bounded cardinality (9 series at most). Reset on process restart. Operators use this to confirm the CNI plugin is the primary enrollment path (`success` rate climbs) versus the watcher fallback (`success` rate stays at 0 even though pods are enrolled).

Socket lifecycle failures use
`ferrum_node_agent_cni_socket_lifecycle_total{reason}` with the closed reasons
`ownership_conflict`, `ownership_io_error`, `stale_socket_cleanup_error`,
`handoff_identity_error`, and `shutdown_cleanup_error`. The corresponding
structured log carries the same `reason`; an ownership conflict is an explicit
startup refusal, not stale-file recovery.

### Deferred follow-ups (not in scope for this PR)

- Install verification (probe to confirm `/opt/cni/bin/ferrum-cni` is present after upgrade).
- CNI upgrade dance (in-place binary swap without disrupting in-flight kubelet calls).
- Rollback (auto-remove the conflist + binary if the node-agent never comes up).
- Admission-time validation of pod CNI metadata.
