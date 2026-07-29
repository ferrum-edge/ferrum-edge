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

### Startup rollback of pinned eBPF state

`load_programs` pins original-destination maps under `/sys/fs/bpf/ferrum`. Those pins outlive a dropped userspace object, so a failed startup must not rely on the backend's `Drop` alone.

Cleanup ownership is handed off between exactly two owners, so `cleanup_all` runs exactly once on every path after a successful load:

1. **During initialization** — from the moment `load_programs` succeeds until `initialize_backend` returns `Ok`, a rollback guard owns the pins. Any later failure inside map/config/SOCK_OPS/readiness setup, and any unwind out of those steps, calls `cleanup_all` before returning.
2. **After initialization** — `run_with_backend` takes ownership and cleans up exactly once for every remaining exit: Kubernetes client construction failure, ordinary watcher-loop shutdown (signalled shutdown, or the watcher stream ending — a transient watcher *error* is logged and retried by kube-rs, it does not exit the loop), and `Drop` on unwind.

The guard is armed strictly *after* `load_programs` returns `Ok`. A failure in `load_programs` itself created nothing this process owns, so it must not run `cleanup_all` — unpinning there could tear down maps a different, still-healthy node-agent owns.

Both owners latch on the first cleanup, so the handoff can never double-clean, and both do their cleanup synchronously — there is no async teardown in `Drop` and no background cleanup task. Cleanup failures are surfaced as structured warnings; the original startup/runtime error is always the returned cause.

Ordering on the normal shutdown path is per-pod first, then node-global: enrolled pods are detached (dropping their registry entries and readiness markers) before `cleanup_all` tears down the shared maps and pins. The `Drop` safety net has no access to the pod table, so it performs the node-global `cleanup_all` only; it exists to guarantee the pins are released, not to substitute for an orderly shutdown.

## Pod Lifecycle Events

The node-agent watches pods on the local node via kube-rs (`spec.nodeName={node_name}` field selector) and reacts to three Kubernetes event flavors. `Event::Apply` from the watcher conflates "added" and "modified", so the same code path handles initial enrollment and mid-life updates.

Watcher-loop exit is classified deliberately: an operator-requested shutdown still runs BPF/CNI cleanup and returns success (process exit 0). If the Kubernetes pod-watcher stream ends unexpectedly, the same cleanup path runs, then the mode returns an error so `main` exits nonzero and supervisors that restart only failed processes relaunch the agent. Transient watcher *errors* are logged and retried by kube-rs; they do not exit the loop. The tie-break is deterministic rather than whichever branch the runtime happens to poll first: an operator shutdown observed at any point up to and including the poll that reports end-of-stream classifies as shutdown (exit 0), so a SIGTERM racing a closing watcher never produces a spurious failure exit. Both exits drop `/health` readiness, signal the shutdown watch (so the CNI listener task cannot outlive the loop), detach BPF state exactly once, then join the listener.

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

### Inbound TC ingress redirect (issue #3287)

Attaching `ferrum_tc_inbound` to the pod veth *guards* direct-to-pod traffic but
does not steer it anywhere: without a redirect, obtaining a fully eBPF-owned
inbound path meant falling back to a node-global `nat PREROUTING -j REDIRECT`.
`ferrum_tc_ingress_redirect` closes that gap.

Set `FERRUM_NODE_AGENT_INGRESS_REDIRECT_IFACES` to a comma-separated list of the
node's capture interfaces (typically the node uplink, e.g. `eth0`). **Unset is
the default and the whole datapath stays inert** — the capture config publishes
a zero redirect mark and the classifier returns every packet untouched before it
performs a single map lookup, so an existing node behaves exactly as it did
before. The variable is NodeWaypoint-only; setting it in `local_pod` proxy mode
is a startup error, because there is no inbound relay to steer traffic into.

The classifier is attached **per node interface, once at startup** — not per pod
— on the tc **ingress** hook only (`bpf_sk_assign` is ingress-only). Off-node
traffic to a pod is only visible on a tc ingress hook before routing decides to
forward it, which is why the attach point is a node interface rather than a pod
veth. Scoping is done per packet by the BPF maps, not by the attach point:

1. the destination must be an enrolled pod (`FERRUM_POD_IPS` / `FERRUM_POD_IPS6`)
   carrying `POD_CAPTURE_FLAG_INBOUND_REDIRECT`, **and**
2. the exact `(pod address, destination port)` pair must be present in
   `FERRUM_POD_INBOUND_PORTS` / `FERRUM_POD_INBOUND_PORTS6`.

Those port entries are derived from the pod's declared TCP `containerPorts` at
enrollment **and re-derived on every later pod event** (see *Lifecycle* below).
Kubernetes probe ports are deliberately *not* folded in — they keep
their existing direct-to-pod exemption through `FERRUM_NODE_PROBE_PORTS`, so
kubelet health checking never depends on the relay being up. A pod that declares
no inbound TCP port is never flagged, and traffic to an enrolled pod on an
undeclared port is left to the direct-pod guard.

Fragmented IPv4 datagrams are declined outright, before any port is read: only
the first fragment carries the TCP ports at all, and a *non-first* fragment's
payload begins with arbitrary application bytes that would otherwise be parsed
as ports at `IHL` and could be made to match any declared `(pod, port)` pair.
Both the More-Fragments and non-zero-offset cases return `TC_ACT_OK`, so a
crafted fragment can neither be steered nor dropped as some other flow. IPv6
stays fail-safe the same way: only a bare TCP next-header is parsed, so a
fragment or extension-header chain passes through to the direct-pod guard.

**No NAT, and original destination metadata is preserved for free.** The packet's
addresses are never rewritten. The classifier resolves the capture listener's
socket and attaches it to the skb with `bpf_sk_assign()`, so the accepted socket
reports the workload's real `podIP:appPort` from `getsockname()` — no conntrack
table, no reverse NAT, no checksum rewriting. An already-established flow is
assigned back to its own socket before the listener is considered, so mid-flow
packets are never re-dispatched.

#### The steer target is a capture listener, not the HBONE listener

The redirect steers into a **dedicated transparent inbound capture listener**,
bound on `FERRUM_MESH_INBOUND_LISTEN_ADDR` (default `0.0.0.0:15006`, which
NodeWaypoint topology otherwise leaves unused). It is deliberately **not** the
HBONE listener on `:15008`.

HBONE terminates authenticated HTTP/2 CONNECT over verified mesh mTLS. What the
redirect carries is ordinary application traffic — plaintext HTTP, Redis,
Postgres, or the application's own TLS — and `IP_TRANSPARENT` preserves
addresses; it does not transform a payload. Steering captured bytes at the HBONE
listener would attempt a mesh TLS handshake on application data and fail. The
two listeners are separate protocol boundaries, and both ports are in the
classifier's bypass set so neither is ever fed its own traffic.

**The bind address decides which families are redirected.** `bpf_sk_assign`
resolves the listener with a wildcard socket lookup in the packet's own address
family, and the kernel never returns an `AF_INET` socket for an IPv6 lookup. A
`0.0.0.0` bind (the default) is therefore invisible to the classifier's IPv6
path, so the node-agent publishes **IPv4 redirect scope only** in that case and
logs which families it armed at startup; enrolled pods' IPv6 inbound traffic
keeps its existing direct-pod behavior rather than being dropped fail-closed.
The per-family flag and the per-family scope are derived together, so an
IPv4-only bind also *clears* any IPv6 scope for the pod's address (a pinned map
can outlive a previous dual-stack configuration) and never sets the IPv6
redirect flag — a true flag paired with unreachable scope is the fail-closed
drop case. Policy routing follows the same family gate: an IPv4-only listener
installs only the IPv4 rule and route, so a host with IPv6 disabled cannot
abort otherwise-valid IPv4 capture during an `ip -6 route` operation.
Bind `FERRUM_MESH_INBOUND_LISTEN_ADDR` to `[::]:15006` — dual-stack under the
default `bindv6only=0` — to redirect both families.

The capture listener terminates nothing. It:

1. recovers the original destination from `getsockname()` (there is no NAT to
   consult) and refuses anything that carries no captured destination — it is
   not a general-purpose relay anyone on the node may address;
2. resolves that destination to **exactly one workload in this NodeWaypoint's
   capture destination inventory** — the workloads whose trusted
   `Workload.node_waypoint.spiffe_id` names this exact NodeWaypoint, on a port
   that workload declares. This is strictly stronger than the inbound HBONE
   relay's open-relay guard (which admits any slice-declared workload address,
   and loopback): the address must belong to a pod this NodeWaypoint is enrolled
   for. No matching workload, an empty inventory, or two records claiming the
   address with divergent identity closes the connection. This gate runs first
   because both gates below are properties of that workload, not of the
   listener;
3. consults the **live PeerAuthentication posture of that exact destination
   workload** on the captured app port, resolved from the workload's own
   namespace/labels with the canonical resolver (`WorkloadSelector` >
   `Namespace` > mesh-wide, port override inside the winner) over the
   PeerAuthentication candidates carried alongside the capture inventory. It is
   deliberately *not* the listener-wide `modes_by_port` table: one NodeWaypoint
   listener serves every enrolled pod on the node, so a port-keyed posture would
   let a `PERMISSIVE` pod admit direct plaintext to a `STRICT` pod that happens
   to share the app port. It is equally deliberately *not* the proxy's own
   `peer_authentications` view: that is narrowed to the NodeWaypoint's
   subscription namespace, so a captured pod in **another** namespace would
   resolve against no policy at all and fall back to Istio's `PERMISSIVE`
   default. Direct captured plaintext is admitted only where the destination's
   own posture permits it; under `STRICT` it is refused and the peer must arrive
   over authenticated mesh transport instead. Enabling the redirect therefore
   does not weaken STRICT, including across namespaces;
4. runs the L4 `on_stream_connect` chain, including the mesh-injected
   `__mesh_authz`, with the captured **app** port as the authorization
   destination and the destination workload's policy scope stamped on the
   stream context — so namespace/selector-scoped `AuthorizationPolicy` rules are
   evaluated against the captured destination rather than denied `scope_missing`
   — then relays byte-for-byte. Application TLS is carried opaquely and is never
   mistaken for mesh TLS.

**Cross-namespace destinations.** A NodeWaypoint usually runs in an
infrastructure namespace while the pods it captures for do not. The control
plane therefore resolves a dedicated, least-privilege inventory for this
subscription — the enrolled destination workloads plus the PeerAuthentication
candidates applicable to them — and carries it on its own slice fields
(`node_waypoint_capture_destinations`, `node_waypoint_capture_peer_authentications`)
over native MeshSubscribe, xDS ECDS carriers, and the file source alike. It is
authorized before it leaves the control plane (CP namespace scope plus the
bearer `ns` claim, with a `Single`-scope control plane a hard boundary), and it
never widens the ordinary `workloads` / `services` / `peer_authentications`
views. A control plane that emits no inventory, an unauthorized namespace, an
unknown NodeWaypoint identity, and a pod enrolled on a *different* node's
NodeWaypoint all resolve to nothing and the connection is refused. See
[`docs/mesh.md`](mesh.md) for the full contract.

Every one of those gates is fail-closed: an unresolvable or ambiguous
destination, or a posture that cannot be established, closes the connection
instead of relaying it under some other workload's policy. Sidecar inbound
relay entries are unaffected — they carry no socket mark and no destination
scope, exactly as before.

The backend dial carries `SO_MARK = 0x734`, so the pod-veth `ferrum_tc_inbound`
guard admits it as an authorized relay dial and the ingress redirect bypasses it
as already-relayed instead of steering it back in a loop.

Because the accepted socket's local address is the pod's (not an address
configured on the host), the capture listener — and **only** that listener —
binds `IP_TRANSPARENT` / `IPV6_TRANSPARENT`; the kernel otherwise refuses to
route a reply from a non-local source. The capability is never conferred on the
HBONE or admin listeners. It must bind a **wildcard** address, because
`bpf_sk_assign` resolves it with a wildcard socket lookup; a specific-IP bind is
invisible to the classifier and the node-agent refuses to start rather than
black-hole every captured connection.

The mesh proxy reads the same operator variables the node-agent does, so there
is no IPC to keep in sync: `FERRUM_NODE_AGENT_INGRESS_REDIRECT_IFACES` decides
whether the capture listener exists at all, and `FERRUM_MESH_INBOUND_LISTEN_ADDR`
is the single source of truth for its port on both sides. The Helm chart renders
both into **both** the node-agent DaemonSet and the ambient NodeWaypoint
DaemonSet from the single `nodeAgent.ingressRedirectIfaces` value. Setting them
by hand outside the chart means setting them on both pods. Startup fails closed
if the two contracts cannot agree: the node-agent rejects a zero, non-wildcard,
HBONE-colliding, or outbound-capture-colliding capture port before it attaches
anything; the **mesh proxy** independently refuses to start when the redirect is
requested and `FERRUM_MESH_INBOUND_LISTEN_ADDR` is malformed, zero-port, or
non-wildcard (validated with a field-specific error at the top of the serving
path, because listener *planning* is infallible and would otherwise only warn
and drop the listener); and a capture listener that cannot bind (including a
failed `IP_TRANSPARENT`) fails the proxy's listener readiness. For the same reason
`nodeAgent.ingressRedirectIfaces` requires `ambient.enabled=true` with
`ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint` — the redirect fails closed, so
enabling it without a capture listener on the node would drop all in-scope
inbound traffic.

Assigned packets still need to be classified as locally deliverable, so the
node-agent installs a Ferrum-owned policy route per family:

```
ip [-6] rule add priority 101 fwmark 0x735 lookup 33134
ip [-6] route replace local <default> dev lo table 33134
```

The RPDB is scanned in ascending priority order, so priority `101` — numerically
lower than the kernel `main` rule at 32766 — is evaluated **before** `main`. A
higher-numbered rule would never be reached: `main` would resolve the marked
packet first and the redirect would black-hole. Table
`33134` is distinct from the UDP TPROXY table `33133`, so tearing one path down
never reaps the other, and deletion always names the exact priority and table
rather than flushing. Routing is installed **before** the classifier is attached
and removed only once the classifier is **provably gone**, so neither ordering
can strand an assigned packet with no local route.

Teardown is retry-safe, and asymmetric on purpose. A live classifier *without*
its routing is the harmful half-state — it keeps assigning packets to the
capture socket while `main` forwards them to the pod, so they reach neither
endpoint — whereas an inert leftover rule only claims the fwmark. So:

- a failed detach **retains** its attachment (the tc links are owned by the
  backend, not by the program's link map, and a failed netlink delete is rebuilt
  from the filter's `(ifname, attach type, priority, handle)` identity), so
  `cleanup_all` is a genuine second attempt rather than a no-op;
- the Ferrum-owned rule and route are removed **after** that retry, and only
  when nothing is still recorded as attached. If the classifier still cannot be
  proven gone, the routing is deliberately left in place and the failure is
  logged with the manual remediation (`tc filter del dev <iface> ingress`);
- every unsuccessful startup path follows the same order — a failed attach on
  any one interface and a `validate_startup_ready` failure that lands after the
  classifier attached both detach first and release the routing through that
  single gate. The one exception is a partially applied routing install (the
  `ip` batch is not atomic): no classifier has attached there, so the
  Ferrum-owned rule/route is removed in place.

Removal always names the exact priority and table, never flushes, and is
best-effort — but not unobserved: a teardown `ip` command that runs and exits
non-zero for any reason other than "no such rule/route" is reported with its
(bounded) stderr, because Ferrum-owned routing left claiming the fwmark can
interfere with other software and would silently pre-satisfy a later reinstall.

A failure to install routing, or to attach on any one interface, is fatal: the
node-agent unwinds what it installed, reports
`ferrum_mesh_node_topology_degraded{reason="node_waypoint_ingress_redirect_unavailable"}`,
and refuses readiness rather than serving a half-installed redirect. The image
therefore needs `iproute2` (`ip`) and `NET_ADMIN` — the same capability the
existing tc and cgroup attachments already require. No new privilege is added.

**Loop and self-capture prevention** — four independent guards, any of which
returns the packet untouched:

| Guard | Why |
|---|---|
| `skb->mark == 0x734` (relay auth mark) | The relay's own authorized dial down to the local backend pod; redirecting it would feed the relay its own traffic. |
| `skb->mark == 0x735` (redirect mark) | Already redirected by this program; never redirect twice. |
| `dst_port == ingress capture port` | Already addressed to the capture listener — the self-capture guard proper. |
| `dst_port == hbone_redirect_port` | Peer-to-peer HBONE, which must reach the HBONE listener directly and must never be re-steered as plaintext. |

**Fail-closed.** A packet that IS in scope but for which no capture-listener
socket resolves is dropped, not delivered — delivering it would silently bypass
`mesh_authz` for exactly the traffic the operator asked to capture. Out-of-scope
packets are never dropped by this program.

**Lifecycle.** Scope entries are written *before* the pod-IP map carries the
redirect flag (flagging first would open a window where in-scope traffic fails
closed with no reachable port), and cleared *after* the pod-IP entry is removed
on teardown (the pod-IP removal alone already disables the redirect). Removal is
keyed by pod address rather than an enumerated list, because a Kubernetes delete
event carries no spec snapshot.

A `containerPorts` edit on a **live, already-enrolled** pod is reconciled on the
Apply/Modified event itself — Kubernetes conflates "added" and "modified", so
this is the update/reload path — with no re-attachment of any program. Each
address family converges independently and in the order that never exposes a
true flag with unusable scope: *installing or widening* writes the scope first
and raises the flag second; *removing every declared port* lowers the flag first
and clears the scope second; a *narrowing* between two non-empty sets is one
wholesale replacement, so a removed port stops matching immediately. Disabling
the redirect (or losing IPv6 support) converges the affected family to empty
scope and a false flag. A failed map or pod-IP write is a visible, retryable
capture failure: the node-agent records `record_attach_error`, keeps the pending
capture-failure marker, and does **not** advance its tracked scope, so the next
pod event recomputes the same delta and converges once the transient condition
clears.

This does **not** remove the node-global iptables fallback: that path exists for
kernels which cannot run eBPF at all
(`FERRUM_NODE_AGENT_FALLBACK_MODE=iptables`, see *Kernel Fallback* below) and is
a separate concern from the covered eBPF path. What changes is that an
eBPF-capable node no longer has to accept node-global REDIRECT semantics to get
an inbound capture path.

Like the rest of the in-netns datapath this is Linux-only and gated by
live-kernel CI. The required `ebpf-live` job:

- load/verifies the program on a real kernel — the only way to check the
  `bpf_skc_lookup_tcp` / `bpf_sk_assign` / `bpf_sk_release` reference-tracking
  rules the verifier enforces on every branch;
- attaches and detaches it on a scratch veth tc ingress hook, asserting the
  classifier is present after attach, absent after detach, and that a second
  detach is a clean no-op;
- round-trips both address families of the scope maps through write, narrow,
  and clear;
- and **drives a real TCP flow end to end**: a client in a scratch network
  namespace connects to a pod address that is configured nowhere on the host,
  the classifier steers the flow into the transparent capture listener, the
  relay asserts the original destination it observes on the accepted socket is
  exactly that `podIP:appPort`, replies, and the reply reaches the client —
  which is only possible because the socket is transparent. It then detaches,
  clears the scope, and asserts the same dial is no longer steered, covering
  cleanup as well as the happy path. The production `ip rule` / `ip route`
  argument vectors are taken from the node-agent itself, so the test proves the
  shipped routing shape actually delivers.

The decision table — arming, scope, all four loop-prevention bypasses, and the
IPv4 fragment gate — is unit-tested in `ferrum-ebpf-common`, and the port
contract (`validate_ingress_redirect`, wildcard capture address) in
`src/ebpf/mod.rs` and `src/modes/mesh/mod.rs`.

Every prerequisite the live datapath test needs routes through the same
skip-or-fail gate as the rest of the live suite, so under
`FERRUM_LIVE_TESTS_REQUIRED=1` a runner or kernel that cannot support the
mechanism fails the gate rather than reporting the feature ready.

Residual risks: the `ip rule` priority is evaluated ahead of `main` and the table is
Ferrum-owned, but a cluster running its own low-priority rules could still order
ahead of it (verified only by the rule-shape unit tests); and the attach point is
operator-supplied, so naming the wrong interface yields no redirect (traffic
simply never reaches the hook) rather than a wrong one, with no auto-detection
or validation.

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

`nodeAgent.probes` configures independently toggleable startup/liveness/readiness
checks. Defaults exec `ferrum-edge health --live` for startup/liveness and
`ferrum-edge health` for readiness against the chart-managed admin listener.
When admin is disabled or `nodeAgent.admin.port=0`, computed probes are omitted
unless a per-probe `override` handler is supplied — the same historical
no-readiness behavior used before startup/liveness were added.

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
`handoff_identity_error`, `handoff_publication_error`, and
`shutdown_cleanup_error`. The corresponding structured log carries the same
`reason`; an ownership conflict is an explicit startup refusal, not stale-file
recovery.

### Deferred follow-ups (not in scope for this PR)

- Install verification (probe to confirm `/opt/cni/bin/ferrum-cni` is present after upgrade).
- CNI upgrade dance (in-place binary swap without disrupting in-flight kubelet calls).
- Rollback (auto-remove the conflist + binary if the node-agent never comes up).
- Admission-time validation of pod CNI metadata.
