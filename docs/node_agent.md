# Node Agent Capture Contract

`FERRUM_MODE=node_agent` runs the per-node capture manager separately from mesh proxy mode. It owns only capture enrollment, eBPF map programming, and the narrow IPC surface described here; it does not merge policy evaluation or proxy dispatch into the node-agent process.

For the security posture of this mode (required Linux capabilities, mounts, seccomp / AppArmor profiles, NetworkPolicy, compromise containment), see [`docs/node_agent_security.md`](node_agent_security.md).

## Contract Surface

`CaptureContract` formalizes the node-agent to proxy boundary:

| Surface | Name / default | Purpose |
|---|---|---|
| Proxy mode | `FERRUM_NODE_AGENT_PROXY_MODE=local_pod` | Selects the capture topology. `local_pod` redirects to the co-located pod proxy. `node_waypoint` drives the sidecarless node-waypoint datapath: per-pod dual-family in-netns capture listeners, the GAP-2M socket-cookie bridge, the pod registry, and the direct-inbound pod-veth guard (see below). The remote `node-waypoint-ebpf-live` workflow gates IPv4 and IPv6 capture, secured node-to-node transport, SPIRE-backed identity, direct Pod-IP bypass checks, source workload IPv4 reuse, HBONE negative authentication probes, and SPIRE/NodeWaypoint restart recovery. |
| Admin listener | `FERRUM_NODE_AGENT_ADMIN_ENABLED=false` | Opts in to the read-only admin listeners for node-agent metrics/health. When enabled, `FERRUM_ADMIN_HTTP_PORT` and `FERRUM_ADMIN_HTTPS_PORT` control plaintext and TLS listeners independently (port `0` disables that transport only). HTTPS uses the shared `FERRUM_ADMIN_TLS_*` contract and fails closed on explicit TLS intent without server cert/key. The listener defaults to loopback unless `FERRUM_ADMIN_BIND_ADDRESS` or `FERRUM_ADMIN_ALLOWED_CIDRS` is set. `/live` is always unauthenticated/minimal; unauthenticated `/health` returns only `status`/`ready`; `/metrics` requires admin JWT, metrics bearer token, or metrics CIDR. |
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

Accept-to-first-byte observability follows the same generation boundary. The
node-agent attaches SK_SKB stream parser/verdict programs to a bounded
accepted-socket SOCKHASH and keeps timestamp/phase evidence in a 65,536-entry
LRU map. First data deletes the correlation state and emits the socket cookie;
the mesh-proxy ringbuf consumer then queues the SOCKHASH entry for removal after
a bounded 250 ms parser/verdict grace period. That userspace queue is also
capped at 65,536 entries. Terminal close deletes state and the
kernel unlinks the closed socket from the SOCKHASH. If the ringbuf is full, the
pass-only hook remains until close rather than risking callback-lock recursion.
Failed handoff deletes state immediately.
`cleanup_all` drops the whole map generation and its pins, so reload cannot
correlate a new socket with stale evidence. In-flight samples across reload are omitted,
not reconstructed. These hooks are observability-only and always pass traffic;
capture identity and its fail-closed readiness contract remain authoritative.

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
| `ferrum_node_agent_capture_state{state}` | Gauge. Exactly one state is `1`: `starting`, `ready`, `unavailable`, `partially_attached`, `identity_bridge_unavailable`, `interface_topology_unavailable`, or `node_global_fallback`. Readiness is only reported after startup BPF maps/programs are loaded and, in NodeWaypoint mode, the SOCK_OPS identity bridge and any configured ingress-interface topology are proved. |
| `ferrum_node_agent_ingress_interface_topology{state,reason}` | Gauge for the optional NodeWaypoint ingress-interface proof. `state` and `reason` are closed sets; configured interface names, route destinations, node addresses, and other host/Kubernetes values are never labels. Notable bounded reasons include `no_remote_topology_evidence`, `node_set_too_large`, `requirement_set_too_large`, and `datapath_update_failed`. |
| `ferrum_node_agent_ingress_interface_configured_interfaces`, `ferrum_node_agent_ingress_interface_expected_interfaces` | Bounded counts for the explicit operator set and the complete route-derived set. Names are deliberately omitted. |
| `ferrum_node_agent_ingress_interface_family_required{family}`, `ferrum_node_agent_ingress_interface_family_covered{family}` | Closed `ipv4`/`ipv6` gauges showing which families the observed remote PodCIDRs require and whether the current topology proof covers them. |
| `ferrum_mesh_node_topology_degraded{reason}` | Gauge. `1` with `reason` ∈ {`kernel_too_old`,`cgroup_v1`,`bpffs_missing`,`ebpf_feature_disabled`,`capture_mode_not_ebpf`,`capture_unavailable`,`node_waypoint_sock_ops_unavailable`} when startup cannot provide the requested eBPF topology. `0` with `reason="none"` when the eBPF capture path is nominal. Cardinality is bounded per node (a single series at a time). |

`ferrum_node_agent_ingress_interface_topology` emits only the current active
`state`/`reason` series with value `1`; it does not emit every possible state as
`0`/`1` like `ferrum_node_agent_capture_state`. Alert on
`ferrum_node_agent_ingress_interface_topology{state!="ready"} == 1`, and add
`absent(ferrum_node_agent_ingress_interface_topology)` when an absent node-agent
scrape must also page.

The NodeWaypoint proxy's authenticated `/metrics` additionally exposes
`ferrum_mesh_bpf_accept_to_first_byte_microseconds`. It measures from the
captured accepted socket's passive-established timestamp to its first non-empty
inbound application-data buffer. The histogram has fixed microsecond buckets
and no connection, address, port, namespace, identity, or cookie labels. See
[BPF SOCK_OPS observability](mesh.md#bpf-sock_ops-observability-gap-sc3) for
correlation, eviction, and missing-evidence behavior.

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
>   the release pipeline's `docker-ebpf` job using the root `Dockerfile` target
>   `runtime-ebpf` with `--build-arg FEATURES=cloud-secrets,ebpf`, which compiles
>   in the aya loader
>   **and** embeds the compiled `ferrum-ebpf` BPF ELF (see "Building the capture
>   image" below). It is **Linux-only** (linux/amd64 + linux/arm64; the aya
>   kernel loader compiles only on Linux) and requires a node kernel **≥ 5.7**
>   with cgroup v2 and the capabilities in
>   [`docs/node_agent_security.md`](node_agent_security.md): on kernel ≥ 5.8
>   `CAP_BPF`/`CAP_NET_ADMIN`/`CAP_PERFMON`; on the 5.7.x window `CAP_SYS_ADMIN`
>   (+ `CAP_NET_ADMIN`), because `CAP_BPF`/`CAP_PERFMON` did not exist until 5.8.
>   `node_waypoint` mode additionally requires `CAP_SYS_ADMIN` on all supported
>   kernels because enrollment enters pod network namespaces with `setns()` to
>   resolve host-side veth peers before attaching pod-veth tc classifiers. The
>   published `-ebpf` runtime remains distroless but includes the `ip` executable
>   and its resolved runtime-library closure, which the exact NodeWaypoint
>   ingress policy-rule lifecycle requires. It still omits a shell, package
>   manager, and `iptables`/`ip6tables` — that omission is deliberate and is not
>   relaxed for any consumer.
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
> - **`-ebpf-tools` (tools-capable capture runtime, Linux-only).**
>   `ferrumedge/ferrum-edge:<tag>-ebpf-tools` /
>   `ghcr.io/ferrum-edge/ferrum-edge:<tag>-ebpf-tools` are built by the SAME
>   release job (`docker-ebpf`), from the same source and the same `FEATURES`,
>   using the root `Dockerfile` target `runtime-ebpf-tools`. It is a strict
>   **superset** of
>   `-ebpf` (identical binaries and BPF ELF) on a Debian 13 base that also ships
>   `/bin/sh`, `ip`, `iptables`, `ip6tables`, `iptables-save`, and
>   `ip6tables-save`. Use it for the two paths that shell out: the Ambient UDP
>   capture lifecycle (the mesh chart selects this tag automatically) and
>   `FERRUM_NODE_AGENT_FALLBACK_MODE=iptables`. It is **not distroless**, has a
>   package manager, and runs as **root**, so prefer `-ebpf` wherever the tool
>   contract is not required.
>   Its manifests are published by `docker-ebpf-tools-manifest`, which `needs:`
>   the same core release path plus `docker-ebpf-manifest`, so the tools tags
>   are never published for a release whose core artifacts or `-ebpf` variant
>   did not ship. `create-release` and `attest-release-images` both `needs:` it,
>   so it is Cosign-signed on its immutable multi-arch digest in both registries
>   and carries SLSA provenance plus per-platform SPDX SBOM attestations exactly
>   like the other two families — see `docs/ci_cd.md`.

**Building the capture image.** The compiled BPF ELF and the `--features ebpf`
binary are produced by the explicit target:

```bash
docker build --target runtime-ebpf --build-arg FEATURES=cloud-secrets,ebpf .
```

The `docker-ebpf` job in
[`.github/workflows/release.yml`](../.github/workflows/release.yml) publishes it
as the `-ebpf` release variant:

- The `ebpf-builder` stage installs the architecture-specific upstream
  `bpf-linker` 0.11.0 static release after verifying its repository-pinned
  SHA-256 digest, installs nightly + `rust-src`, and runs
  `cargo +nightly build -p ferrum-ebpf --target bpfel-unknown-none -Z build-std=core --release`
  (the `ebpf/rust-toolchain.toml` pins the nightly). The ELF is COPY'd into the
  runtime image at `/app/bpf/ferrum-ebpf`, and `FERRUM_NODE_AGENT_BPF_ELF_PATH`
  defaults to that path.
- The main binary must be built with `--build-arg FEATURES=cloud-secrets,ebpf`
  to compile in the aya loader. The root Dockerfile's default final `runtime`
  target is the ordinary gateway contract and ships neither the BPF ELF nor
  `ip`; the explicit `runtime-ebpf` target adds both. Enabled eBPF node-agent
  mode still rejects a mock backend before readiness, sets the
  degraded/capture-state metrics, and exits instead of silently reporting Ready.

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
tasks/netns handle instead of tearing down into plaintext. Live
bind-collision/source-capture verification is enforced by
`functional_mesh_live_source_capture_udp_manager_hbone_round_trip` (closed
[#2013](https://github.com/ferrum-edge/ferrum-edge/issues/2013) /
[#2038](https://github.com/ferrum-edge/ferrum-edge/issues/2038)). The
enrolled-destination two-pod UDP round trip (destination pod-netns relay plus
tc-inbound admit) is not yet live-gated — tracked on
[#3621](https://github.com/ferrum-edge/ferrum-edge/issues/3621).

The Ambient UDP producer needs the same host access the NodeWaypoint in-netns
listener needs — the read-only host cgroup mount + host `/proc` to resolve pod
netns and `SYS_ADMIN`/`SYS_PTRACE` for `setns(CLONE_NEWNET)` — plus **`NET_ADMIN`**
to install the in-netns `iptables`/`ip` TPROXY rules and to bind the
`IP_TRANSPARENT` capture and reply sockets, and `iptables`/`ip6tables`/`ip`/`sh`
present in the proxy image. Its rules live **only** inside each pod netns; the
node-agent's own host-netns iptables fallback emits none (there is no
host-netns-safe `addrtype` direction discriminator, and the node-agent has no UDP
listener to serve them).

### Host-network UDP capture placement (issue #3288)

`FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED=true` on the **ambient proxy** (with
`FERRUM_MESH_CAPTURE_UDP_ENABLED=true`) moves UDP source-capture into the proxy's
own network namespace instead. The **node-agent's role is unchanged**: it still
publishes the per-pod registry and still keeps each pod's BPF UDP gate closed
until the producer publishes `<registry_dir>/.udp-ready/<pod_uid>`, and it still
installs no UDP rules of its own. What changes is where the rules and the socket
live. A readiness-marker write that fails after capture becomes live is retried
on every otherwise-idle producer reconcile; only a successful publication is
recorded as ready, so a transient registry I/O failure cannot strand the pod's
BPF gate permanently closed.

The producer also drives the same **gate-close handshake** the pod-netns producer
uses when a pod stops being captured: it persists
`<registry_dir>/.udp-ack-required/<pod_uid>`, retracts `.udp-ready`, and keeps the
pod's host capture rule in place behind a DROP guard until the node-agent
publishes `<registry_dir>/.udp-not-ready/<pod_uid>`. Retracting readiness does not
close the BPF gate synchronously, so removing the rule first would let that pod's
UDP egress leave the node in plaintext for as long as the node-agent took to
notice.

That handshake also crosses the **process boundary**. Those markers are durable,
so a producer that dies leaves the node-agent holding an open UDP gate for every
pod it had readied — and the node-agent has no way to tell a dead producer from a
busy one. A replacement therefore does not reap the previous generation's host
rules first: it re-issues the close handshake for every pod the durable state
names, waits for `.udp-not-ready`, and only then removes anything. Until it
settles, the predecessor's rules stay installed (a capture path whose socket died
with its process drops rather than leaks) and this generation applies nothing.
The same recovery runs on a node that switched **away** from the host placement.
One bounded pass runs during mesh initialization; if safe marker retraction is
still incomplete, recovery continues in the background and only the replacement
UDP producer waits for that boundary. Other mesh/admin listeners still start,
while predecessor rules retain a fail-closed UDP posture. Once retraction is
complete the producer may safely republish `.udp-ready`; stale host-state reaping
can continue without retracting those new markers. A node-agent that stops
acknowledging therefore leaves those pods' UDP dropped rather than released — the
mesh proxy logs the outstanding pods periodically and keeps retrying.

Direction is discriminated by INGRESS INTERFACE — `mangle PREROUTING -i <the
pod's host-side interface>` — which is exact in the host namespace: a pod's egress
is the only traffic entering there on that pod's own interface, pod-destined
traffic arrives on the node uplink, and the node's own traffic is locally
generated and traverses `OUTPUT` only. **No `mangle OUTPUT` chain is installed at
all**, so node traffic cannot be captured. Each datagram is attributed to a pod by
its ingress interface index plus its registry-published source address; anything
not attributable to exactly one enrolled pod is dropped rather than relayed under
an absent or neighbouring identity, and two pods resolving to one interface are
both refused.

This placement enters no namespace, so the host UDP path needs `NET_ADMIN` and
the capture tools but **not** `hostPID`, `SYS_ADMIN`, or `SYS_PTRACE`; the chart
narrows the ambient DaemonSet's capabilities accordingly while retaining its
baseline `NET_RAW`. It keeps the registry hostPath and the read-only host cgroup
mount (the enrolled-pod set and interface resolution use them), and falls back to
the host route table keyed on the registry-published pod IP when host `/proc` is
not shared — `/proc/net/route` for a v4 address and `/proc/net/ipv6_route` for a
v6 one, so an **IPv6-only** enrolled pod resolves on this path too rather than
being refused for want of an address it does not have. The fallback accepts only
an unambiguous `/32` or `/128` host route, and sysfs must identify the resolved
device as a distinct peer rather than a self-linked bridge/uplink. A broader
route through a shared bridge is refused because it is not per-pod interface
ownership evidence. It requires a CNI that gives each pod its own host-side
interface.
The production host-netns TPROXY datapath is live-gated by the required
`ambient-host-udp-live` workflow ([#3705](https://github.com/ferrum-edge/ferrum-edge/issues/3705)).
Full behaviour, ownership, and the enforced generation-bound cleanup/finalize
workflow are in [`docs/mesh.md`](mesh.md) → "Ambient UDP placement migration".
During cleanup the node-agent retracts `.udp-registry-synced` at relist start and
atomically republishes a bounded proof containing the requested generation and a
fresh publication identity only after `InitDone`; the proxy will not prove
predecessor cleanup from an incomplete registry view. After the relist, every
pod/CNI capture mutation retracts the marker before changing ownership and
republishes a new identity only after registry persistence and retry state
converge. Cleanup compares the exact identity across its repeated passes, so a
same-generation clear/mutate/republish cycle resets accumulated completion. The
generation is bounded operator input and neither it nor the publication identity
is used as a metric label or log field.

Marker publication failures are migration-local: the watcher stays alive,
withholds readiness and proof, and retries. Retraction failures are stricter.
The node-agent keeps the control loop alive but fences watcher Apply/Delete,
CNI ADD/DEL/GC, and capture retry mutations until the stale marker is securely
absent; watcher events are deferred and CNI calls fail retryably rather than
being acknowledged without capture. Shutdown likewise preserves registry
entries instead of running the ordered pod-detach mutation if proof retraction
fails; the backend owner still performs its process-exit cleanup. Publication is bounded in the steady state:
each pod registry entry is atomically file+directory synced when it changes,
while marker publication validates the snapshot and performs one directory
sync instead of fsyncing every live pod on every event.

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

#### Interface topology proof and drift handling

A successful tc attach is necessary but is not readiness evidence. Before the
initial pod relist can advertise readiness, the node-agent completes one paged
Node LIST and retains only the projected evidence used by a long-lived watch,
with a hard maximum of 256 Nodes. Complete `spec.podCIDR`/`spec.podCIDRs` plus
usable same-family `status.addresses[type=InternalIP]` is cluster route evidence
whether that remote Node is Ready, not Ready, rebooting, or draining;
`ExternalIP` is deliberately not route-symmetry evidence. A non-Ready Node with
incomplete evidence is ignored so joining and transiently unhealthy peers do
not invalidate an otherwise complete cluster proof. A `Ready=True` Node with
incomplete or malformed evidence remains a whole-snapshot failure: it may carry
pods whose path must be proved. CNIs/platforms that omit this evidence for every
usable remote Node remain fail-closed.

An explicit redirect on a single-node cluster (or a snapshot with no usable
remote route evidence) has no off-node ingress path to prove, so it reports the
bounded reason `no_remote_topology_evidence`, not `family_unproved`, and remains
unavailable. Leave `FERRUM_NODE_AGENT_INGRESS_REDIRECT_IFACES` unset for that
topology; unset is the supported inert configuration and does not broaden or
alter capture.

Required families come from the observed remote PodCIDRs intersected with the
capture listener's capability. An IPv4-only cluster therefore requires only
IPv4 even when `[::]` provides dual-stack capture, while an IPv6-only cluster is
provable when the capture listener supports IPv6. An IPv6-only cluster with an
IPv4-only capture listener has no applicable family and remains unavailable.
Every required family retains complete per-CIDR and same-family InternalIP
coverage. The configured set must equal the resulting route-selected set
exactly. This covers a single uplink, dual-stack, and multiple route-selected
uplinks without choosing an interface on the operator's behalf.

The supported topology is symmetric routed node/CNI traffic: each remote
PodCIDR and its Node address must resolve into the same proved ingress set. A
split route, equal-cost ambiguity, missing family, overlay shape whose inner and
outer devices diverge, or a route table above the fixed ingestion bounds is
unproved and therefore unavailable. Ferrum never guesses which side of an
overlay owns the hook and never broadens attachment to every interface. Route
ingestion reads `/proc/net/route` and `/proc/net/ipv6_route`, which expose the
kernel main table here; alternate policy-routing tables and rules are not
evaluated. A CNI whose pod/node route proof depends on those alternate tables is
therefore unsupported and remains fail-closed.

Every explicitly configured and route-selected device must exist, have a safe
Linux interface name, be administratively and operationally up with carrier,
be non-loopback, and have a supported L3 link shape. Linux bridges, bonds,
self-linked virtual devices such as dummy links, and tun/tap devices are refused
by this routed-topology implementation. An existing management device that has
no proved remote PodCIDR route role is also refused as an unexpected/wrong
interface rather than accepted because tc can attach to it.

Node changes are derived from the bounded projected cache rather than a fresh
cluster-wide LIST on each tick. A heartbeat whose projected requirements did not
change skips procfs/sysfs validation. Host route/link drift checks remain every
five seconds with a two-second per-pass timeout in a shutdown-owned background
task; the pod/CNI/retry select loop receives completed outcomes through a
latest-value channel and never waits on Kubernetes or filesystem I/O. Structural
overflows stay failed closed and retry a full LIST at most four times per hour
per node-agent instead of entering a fast relist loop. Watch failures emit at
most one redacted warning per minute with only bounded stage/class/status-code
fields; Node values, route values, and raw transport/RBAC errors are omitted.

Link-down, route replacement, family loss, incomplete required evidence, or
Node topology drift withdraws `/health` readiness on the next bounded result,
changes capture state to `interface_topology_unavailable`, and atomically
disarms the ingress redirect mark/port in the BPF capture map. The already
attached classifier then becomes inert, but the existing direct-pod guard stays
fail-closed; already-enrolled workloads can therefore be unreachable until the
proof recovers and must not be considered capture-ready. CNI ADD, CHECK, and
STATUS are rejected throughout that quarantine; DEL and post-sync GC cleanup
remain available. Recovery re-arms the same explicit interface set only after
both the topology and initial pod relist are proved. It never creates a CNI
fail-open, implicit direct-pod fallback, or broader node capture.

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

Residual risk: the `ip rule` priority is evaluated ahead of `main` and the table
is Ferrum-owned, but a cluster running its own lower-numbered rules could still
order ahead of it (verified only by the rule-shape unit tests). The attach point
remains operator-supplied; the node-agent proves that exact set or withholds
readiness, but deliberately does not auto-select or rewrite it.

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
| `fail` (default) | Refuse to start, surface the kernel deficiency in the error log, and exit. This matches the published distroless `-ebpf` image, which includes `ip` for the supported eBPF path but deliberately omits a shell and `iptables`/`ip6tables`. |
| `iptables` | Apply host iptables capture rules and continue serving. This requires a runtime image that includes `/bin/sh`, `iptables`, and `ip6tables` when IPv6 capture is enabled — use the published `:<tag>-ebpf-tools` variant, or your own equivalent. The gauge records the reason; pod-level eBPF enrollment is skipped. Existing pods that were enrolled before degradation keep working until the next reconcile; new pods rely on the iptables capture path. |

Suggested remediations by reason label:

| `reason` | Remediation |
|---|---|
| `kernel_too_old` | Upgrade the node to a kernel >= 5.7. Most modern distributions (RHEL 9 / Ubuntu 22.04 / Debian 12 / Amazon Linux 2023) already satisfy this. |
| `cgroup_v1` | Mount the unified cgroup v2 hierarchy (`systemd.unified_cgroup_hierarchy=1` on systemd hosts). cgroup_sockaddr BPF programs require cgroup v2 and cannot attach to the v1 hierarchy. |
| `bpffs_missing` | Mount `bpffs` at the configured `FERRUM_NODE_AGENT_BPF_FS_PATH`: `mount -t bpf bpffs /sys/fs/bpf`. The DaemonSet manifest in `charts/ferrum-mesh/` mounts this automatically when configured. |

### Mixed-kernel clusters

In a cluster with heterogeneous kernels, the recommended pattern is:

1. Deploy the node-agent DaemonSet to every node with the default `FERRUM_NODE_AGENT_FALLBACK_MODE=fail`; degraded nodes stay NotReady and the startup error identifies the remediation reason.
2. If you intentionally want degraded nodes to keep routing while kernels are upgraded, run a node-agent image that includes `/bin/sh`, `iptables`, and `ip6tables` — the published `:<tag>-ebpf-tools` variant, or your own equivalent — then set `FERRUM_NODE_AGENT_FALLBACK_MODE=iptables` for those nodes.
3. Configure the admission webhook (`FERRUM_MODE=injector`) to inject iptables init containers for pods scheduled on degraded nodes. The injector decides this from a Helm-templated `NodeSelector` driven by your node labels (e.g., `ferrum.io/capture-mode=iptables`).

The mesh control plane is not changed by node-level degradation: slice apply, `mesh_authz`, `mesh_workload_metrics`, and HBONE all continue to function as ambient. Only the per-pod capture mechanism on the affected node changes.

The node agent starts the read-only admin listeners independently for HTTP and HTTPS, matching the other serving modes:

- `FERRUM_ADMIN_HTTP_PORT` controls plaintext. Set to `0` to disable only HTTP.
- `FERRUM_ADMIN_HTTPS_PORT` controls HTTPS. Set to `0` to disable only HTTPS. An explicitly configured nonzero port requires a complete `FERRUM_ADMIN_TLS_CERT_PATH` / `FERRUM_ADMIN_TLS_KEY_PATH` pair and starts the shared reloadable admin TLS listener (optional client CA / CRL / live reload via the existing frontend/admin TLS contract). Invalid, missing, partial, unreadable, mismatched, or malformed TLS material fails startup before plaintext can bind; HTTPS is never silently skipped in favor of plaintext. Explicit TLS intent also includes `FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH`, `FERRUM_ADMIN_TLS_OCSP_RESPONSE_SOURCE`, or `FERRUM_ADMIN_TLS_NO_VERIFY=true` (only `true` is intent): with the inherited default port `9443`, those signals fail closed when server cert/key are absent rather than being silently ignored. The inherited global default `9443` without an explicit port or any of those TLS intent signals remains the raw binary HTTP-only compatibility posture. Port `0` remains the unconditional HTTPS disable sentinel even when TLS intent fields are present.
- Dual nonzero ports supervise both listeners under one connection-limit / JWT / CIDR / metrics-auth / request-limit policy. SIGINT/SIGTERM and capture-loop shutdown join both handles.

The Helm chart sets `nodeAgent.admin.port` to `19090` and `nodeAgent.admin.httpsPort` to `0` by default (HTTP-only, preserving existing installs). Set `nodeAgent.admin.tls.enabled=true` with `secretName` (and a nonzero `httpsPort`) for HTTPS-only (`port=0`) or dual listeners. The chart mounts Secret keys for cert/key and optional client CA / CRL; it does not store PEM in values.

The binary default HTTP port remains `9000`, but the chart uses a different host-network port so an ambient NodeWaypoint proxy and node-agent can run on the same node without an admin listener collision.

`nodeAgent.probes` configures independently toggleable startup/liveness/readiness
checks. Defaults exec `ferrum-edge health --live` for startup/liveness and
`ferrum-edge health` for readiness against the chart-managed admin listener.
HTTPS-only (`port=0` with TLS) appends `--tls --tls-no-verify` and dials
`httpsPort`. When admin is disabled or both ports are unavailable, computed
probes are omitted unless a per-probe `override` handler is supplied — the same
historical no-readiness behavior used before startup/liveness were added.
HTTPS-only mTLS (`tls.clientCaKey` with `port=0`) requires every enabled probe
to be disabled or given an explicit override; startup, liveness, and readiness
are classified independently (overriding only liveness does not cover startup).
Optional `nodeAgent.admin.metricsScrape.enabled` stamps Prometheus scrape
annotations: HTTPS without client auth prefers the HTTPS port/scheme; dual
HTTP + mTLS HTTPS advertises the plaintext HTTP listener because simple
`prometheus.io/*` annotations cannot present a client certificate; HTTPS-only
mTLS with scrape enabled fails at render and directs operators to an external
scrape config/sidecar.

Observability auth on the node-agent admin surface matches the shared admin
contract: `/live` is always unauthenticated and minimal; unauthenticated
`/health` returns only `status` and `ready`, while full diagnostics require
authorization; `/metrics` returns `401` unless authorized by a valid admin JWT,
a matching `FERRUM_METRICS_BEARER_TOKEN`, or a source IP in
`FERRUM_METRICS_ALLOWED_CIDRS`. To prevent an opt-in to
`FERRUM_NODE_AGENT_ADMIN_ENABLED=true` from accidentally exposing those
surfaces beyond the host, the node-agent admin listener defaults to loopback
(`127.0.0.1`) when **none** of the following operator signals are configured:

- `FERRUM_ADMIN_BIND_ADDRESS` is set explicitly (any value, including `0.0.0.0` if intentional), or
- `FERRUM_ADMIN_ALLOWED_CIDRS` is set to a non-empty allowlist.

`FERRUM_ADMIN_JWT_SECRET` alone does not change the bind address; it authenticates
management routes but does not make `/metrics` or detailed `/health` public.
The two bind signals resolve as follows: an explicit `FERRUM_ADMIN_BIND_ADDRESS`
is honored verbatim; an `FERRUM_ADMIN_ALLOWED_CIDRS` allowlist with no explicit
bind binds the listener to `0.0.0.0` (restricted by that allowlist) so an
authorized scrape source can reach `/metrics` — because the bind now defaults
to loopback, the allowlist alone would otherwise leave the listener unreachable.
When neither signal is set, the listener stays on `127.0.0.1` and the gateway
emits a `warn!` at startup pointing at the two opt-ins. For node-agent
deployments scraped over the cluster network, prefer
`FERRUM_ADMIN_ALLOWED_CIDRS` (including the scrape source ranges) together with
metrics auth (JWT, metrics bearer token, or metrics CIDR), or front a local
sidecar scraper bound to loopback.

> **Helm chart users:** the allowlist-only `0.0.0.0` behavior above applies to the **raw env** contract. The `charts/ferrum-mesh` node-agent DaemonSet always renders `FERRUM_ADMIN_BIND_ADDRESS` from `nodeAgent.admin.bindAddress` (default `127.0.0.1`) whenever node-agent admin is enabled, so the bind is always an explicit signal and the allowlist-only branch never engages through the chart. To expose `/metrics` for cluster scraping via Helm, set **`nodeAgent.admin.bindAddress=0.0.0.0`** together with supported env allowlists such as `nodeAgent.env.FERRUM_ADMIN_ALLOWED_CIDRS`, `nodeAgent.env.FERRUM_METRICS_ALLOWED_CIDRS`, and/or `nodeAgent.env.FERRUM_METRICS_BEARER_TOKEN` for the scrape sources; setting only the allowlist leaves a loopback listener and scraping fails.

When ambient NodeWaypoint and the node agent run on the same host-network nodes, their admin listeners must use distinct `FERRUM_ADMIN_HTTP_PORT` / `FERRUM_ADMIN_HTTPS_PORT` values or one listener must be disabled with port `0`. The Helm chart rejects equal host-network admin HTTP ports, equal HTTPS ports only when both sides would actually bind HTTPS (complete admin TLS), node-agent HTTP and HTTPS on the same port when both would bind, and cross-protocol collisions (ambient HTTP vs node-agent HTTPS, ambient HTTPS vs node-agent HTTP) when those respective surfaces are active. Inherited inactive HTTPS defaults without TLS material do not create false conflicts. The binary also treats an enabled admin-listener bind failure as fatal startup rather than continuing to report ready.

## CNI plugin install (optional)

The node-agent's default enrollment path is the kube-rs pod watcher: it polls the Kubernetes API for pods scheduled to its node and reconciles BPF attachment from the resulting label/annotation snapshots. That works but races kubelet — a freshly-scheduled pod may complete its CNI sandbox setup, attach a network namespace, and start sending traffic *before* the watcher has seen the `Apply` event. During that window outbound traffic is not yet routed through Ferrum's eBPF redirect.

The optional CNI-style install closes that window. A small `ferrum-cni` binary, dropped into the host's `/opt/cni/bin/` directory and chained behind the cluster's primary CNI (Calico, Cilium, etc.), forwards each ADD/DEL/CHECK/STATUS/GC invocation from kubelet to the long-lived node-agent over a Unix domain socket. On ADD, the node-agent fetches the pod from the Kubernetes API by namespace/name so it can evaluate labels and annotations immediately; the kube-rs watcher still runs afterward as the source of truth for reconciliation. On STATUS (CNI 1.1.0), the eBPF path probes whether Ferrum can service ADD (node-agent socket reachable, initial pod sync complete, and a live Kubernetes API readiness probe). On GC (CNI 1.1.0), the runtime supplies the still-valid `(containerID, ifname)` attachment set and the node-agent removes only Ferrum-owned CNI attachments absent from that set. The explicit node-global iptables fallback exception is described below.

### Architecture

```
                            ┌──────────────────────────────────────────────┐
                            │                  worker node                 │
                            │                                              │
                            │  ┌─────────┐    /opt/cni/bin/ferrum-cni      │
                            │  │ kubelet │ ───────────────────────┐        │
                            │  └─────────┘                        │        │
                            │       │ ADD/DEL/CHECK/STATUS/GC     ▼        │
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

The CNI plugin and the kube-rs watcher feed the same enrollment path, and the watcher keeps running and reconciling once the plugin is installed. For *enrollment* the CNI hook is therefore an optimization: it closes the kubelet-vs-watcher race, and the watcher would eventually enroll the pod anyway.

> **Availability is a different question, and the answer is a hard dependency.** Installing the chained conflist puts `ferrum-cni` in the ADD path of **every** pod on the node. `ferrum-cni` fails **closed** when it cannot reach the node-agent: a missing socket, a crash-looping or absent node-agent, or an IPC error makes ADD return a CNI error, and kubelet leaves the pod in `ContainerCreating`. So while `nodeAgent.cni.enabled=true`, node-agent availability is a **node-wide pod-creation dependency**, not an optimization. This is the deliberate capture-race posture — passing ADD through unenrolled would silently start a pod outside the mesh — but it must be operated as a dependency.
>
> Three mechanisms bound the blast radius, and none of them is optional reading before you enable this:
>
> - **CNI 1.1 STATUS** lets a 1.1.0 runtime observe that Ferrum cannot service ADD before it tries (see below). It is informational: per spec it does not stop ADD.
> - **Automatic rollback** (`nodeAgent.cni.rollback`, on by default) removes this pod's own CNI artifacts if the node-agent never reaches CNI readiness, so a broken install degrades to watcher-only enrollment instead of a node-wide outage.
> - **Uninstall** (`nodeAgent.cni.uninstall`, on by default) removes the chain from every node during `helm uninstall`, before the socket disappears.
>
> A node-agent that crash-loops *after* it was once ready is **not** rolled back automatically — see "Recovering a node" for the manual path.

STATUS reports whether that node-agent + Kubernetes API dependency is ready for ADD. GC is complementary: it recovers Ferrum capture/enrollment state after missed DEL calls, node crashes, or sandbox metadata loss without relying on watcher timing alone.

### CNI 1.1 STATUS semantics

- **Version gate.** `STATUS` is accepted only when the negotiated `cniVersion` is `1.1.0`. Older versions keep ADD/DEL/CHECK unchanged and fail closed on STATUS with an unsupported-version error.
- **No attachment fields.** STATUS does not carry `CNI_CONTAINERID` / `CNI_IFNAME` / `CNI_NETNS` / `CNI_ARGS`, and must not include `cni.dev/valid-attachments` or other reserved `cni.dev/` keys.
- **Fail-closed readiness.** Success (exit 0, empty stdout) means the node-agent CNI socket answered, the main loop has completed initial pod sync, any configured NodeWaypoint ingress-interface topology is currently proved, **and** a live read-only Kubernetes API readiness probe succeeded (node-scoped pods `list` with `limit=1`, bounded by the same 750ms budget as CNI ADD metadata fetch, well under the 5s CNI RPC timeout). That probe proves the ADD dependency can reach the API with the node-agent's existing get/list/watch permissions; it does not mutate enrollment, BPF, ownership, or GC state. Socket/IPC failure, incomplete initial sync, an unproved ingress topology, or a failed/timed-out Kubernetes probe maps to CNI error code 50 (`plugin is not available`) without echoing socket paths, Kubernetes errors, URLs, tokens, namespaces, or other raw dependency detail.
- **Informational only.** Per the CNI 1.1.0 spec, STATUS does not prevent ADD/DEL/CHECK/GC; those verbs remain independently handled.

### CNI 1.1 GC semantics

- **Version gate.** `GC` is accepted only when the negotiated `cniVersion` is `1.1.0`. Older versions keep ADD/DEL/CHECK unchanged and fail closed on GC with an unsupported-version error. `VERSION` advertises `0.3.0`/`0.3.1`/`0.4.0`/`1.0.0`/`1.1.0`.
- **Valid attachments.** The runtime supplies the CNI 1.1 `cni.dev/valid-attachments` field as `(containerID, ifname)` tuples. Ferrum requires the reserved field even when the list is empty, bounds ingestion (attachment count, field length, safe character set), and rejects omitted, misspelled, hostile, or path-like input before reconciliation.
- **Ownership.** Successful CNI ADD records Ferrum ownership of that attachment in memory and, when the CNI listener is enabled, in a crash-safe durable file beside the configured CNI socket (filename `cni-owned-attachments.<socket-digest>.v2` under the socket parent, typically `/var/run/ferrum/`). Each durable record stores the `(network name, containerID, ifname) -> pod UID` identity plus a bounded cleanup snapshot (attached proof, pod IPs, cgroup map keys, probe ports, inbound redirect scope) so GC can tear down Ferrum-owned eBPF state after a process restart when live `pod_states` is empty. A detached snapshot is not a valid production ownership claim and is rejected during both decode and encode, so it cannot suppress persisted map/rule cleanup. GC is authoritative only for the named CNI network and removes only its Ferrum-owned attachments absent from that network's valid set. A pod with another valid or differently-scoped Ferrum claim keeps its shared capture state. Watcher-only enrollments and other node-agent generations are never swept. Ordinary IP/map updates refresh the durable cleanup snapshot, while a watcher-detected sandbox/veth replacement retires the prior attachment claim after old-generation teardown rather than transferring that claim to the replacement. On node-agent restart, well-formed durable records are rehydrated before GC can act, and GC remains retryable until the initial Kubernetes pod relist completes; malformed, oversized, truncated, non-regular, hard-linked, symlinked, or path-like durable state fails closed (GC errors without sweeping) and never echoes raw hostile identifiers. ADD that cannot durably persist an ownership claim returns an error and does not leave a false in-memory GC claim (kubelet may retry). Durable ownership is cleared only after removal-blocking cleanup succeeds (including backend detach and map/rule teardown driven from the rehydrated snapshot); a durable-update failure retains ownership for retry and must not report success for that clear.
- **Idempotency / partial failure.** Repeat GC with the same valid set is a no-op success once every stale Ferrum-owned attachment is fully cleaned. When ownership refresh or BPF/rule/map teardown leaves removal-blocking state for one stale UID, GC fences that UID and retains its ownership (including durable state), continues reconciling independent stale UIDs, then reports the incomplete work. A later GC re-drives the pending-removal retry path until cleanup is complete. Rehydrated ownership after a process crash carries the cleanup snapshot needed to detach and clear stale eBPF maps/rules; GC never reports success merely because live `pod_states` is empty.
- **Explicit iptables fallback.** The node-global `FERRUM_NODE_AGENT_FALLBACK_MODE=iptables` path has no per-pod eBPF backend or pod watcher. Its CNI passthrough therefore fails ADD/CHECK/STATUS/GC until the fallback rules are fully installed (DEL remains an idempotent no-op). After readiness, STATUS reflects installed node-global capture rather than the eBPF path's pod-relist/API probe because fallback ADD has no per-pod metadata dependency. GC succeeds only when the socket-bound durable ownership file has no stale record for the requested network. A stale record from an earlier eBPF generation is retained and GC returns an error until an eBPF-capable generation can perform the exact teardown; fallback never reports that state reconciled or discards its ownership proof.

### Install steps

The Helm chart at `charts/ferrum-mesh/` ships an opt-in CNI installer init container, gated by `nodeAgent.cni.enabled`. When enabled:

1. The DaemonSet pod starts the rollback watcher as a **native sidecar** (an init container with `restartPolicy: Always`; Kubernetes 1.29+), ordered before the installer so it is already running while the chain is written.
2. The next init container runs `/app/ferrum-cni install`, which copies the binary into the host's `/opt/cni/bin/` (host-path mount).
3. Under the install lock the installer fail-closes if the configured target conflist already exists and is not a same-owner Ferrum-marked regular file, then records an ownership manifest, reads the existing primary CNI config matching `nodeAgent.cni.chainedWith`, preserves its plugin fields/IPAM, appends Ferrum as a meta-plugin, and writes the generated `*-ferrum.conflist` into `/etc/cni/net.d/`.
4. The node-agent container mounts `/var/run/ferrum/` so both the binary and the daemon share the UDS path.
5. Set `FERRUM_NODE_AGENT_CNI_ENABLED=true` (the chart sets this when `nodeAgent.cni.enabled=true`).

Manual install (no Helm): run `ferrum-cni install` on every node with `HOST_BIN_DIR`, `HOST_CONF_DIR`, `HOST_SOCKET_DIR`, `CONF_FILE_NAME`, `CHAINED_WITH`, `SOCKET_PATH`, `OWNER_ID`, and `INSTALL_GENERATION` set, or hand-write the equivalent chained `.conflist` (see "Ownership markers" for what `ferrum-cni uninstall` will and will not remove). Ensure `/var/run/ferrum/` is writable and set `FERRUM_NODE_AGENT_CNI_ENABLED=true`. The default Unix socket path is `/var/run/ferrum/node-agent-cni.sock`; any `FERRUM_NODE_AGENT_CNI_SOCKET_PATH` override must be absolute.

### Ownership markers

Everything the installer writes is stamped so it can be removed again without guessing. `/etc/cni/net.d/` is shared with the cluster's primary CNI and any other meta-plugin, so "delete the file we would have written" is not good enough.

Two pieces of evidence, both written at install time:

- The generated conflist's own `ferrum-cni` plugin entry carries `managedBy: ferrum-edge`, an `owner`, and a `generation`. This lives in the object the CNI spec reserves for this plugin, so no neighbouring plugin can be confused by it, and `FerrumCniOptions` ignores the extra keys on the request path.
- A sibling `/etc/cni/net.d/.ferrum-cni-owned.marker` manifest repeats the ownership, names the exact artifacts it speaks for (`confFileName`, `binaryFileName`), and records the SHA-256 of the binary that was installed. The name has no CNI extension, so no runtime treats it as a network configuration and the installer's own primary-config scan skips it. A manifest that names a different conflist or a different binary is evidence about *those* files and authorizes nothing here.

`previousBinarySha256` is the one field that carries an *older* digest forward, and it is an attestation rather than an observation. Hashing whatever regular file happens to occupy `/opt/cni/bin/ferrum-cni` proves nothing about who owns it — on a first install that file may belong to an operator or another product entirely — so recording that digest would hand cleanup permission to delete a binary Ferrum never owned. The installer therefore writes the field only when the manifest already on disk (a) parses at the current schema, (b) names these exact artifact names, (c) carries this same owner, and (d) already recorded the digest now on disk as one of its own. That is precisely the repeat-upgrade case the field exists for: a crash between the manifest write and the binary rename leaves whichever of the two attested digests is on disk provably Ferrum's. Every other case writes `null`, the pre-existing binary is retained, and — because an unreferenced binary is inert — chain cleanup still succeeds.

`binaryOwned` applies that same evidence rule to the current digest. It is true only when this install publishes the staged inode or a prior same-owner manifest already attested the reused inode. Byte-identical contents alone never transfer ownership: an operator-provided binary may be reused, but it remains in place after the chain is removed.

A third file, `/etc/cni/net.d/.ferrum-cni-install.lock`, is the node's lifecycle lock (see "Ordering, locking, and what the swap checks do not claim" below). It holds no state, carries no CNI extension, and is deliberately left behind by cleanup.

The Helm chart sets `owner` to `<release namespace>/<release name>` — stable across upgrades — and `generation` to the node-agent pod UID.

`ferrum-cni uninstall` removes an artifact only when that evidence is present **and** matches the scope it was given:

| Situation | Conflist | Binary | Exit |
|---|---|---|---|
| Ferrum-owned, owner matches | removed | removed after its digest matches the manifest | 0 |
| Already cleaned | absent | absent | 0 |
| Owned by a different release / generation | retained | retained | 0 |
| Present but carries no Ferrum marker | retained | retained (still referenced) | **1** |
| Symlink, hard link, non-regular file, or oversized | retained | retained | **1** for the conflist |
| Manifest lost or corrupt | removed (the in-file marker is sufficient) | retained (provenance unproven) | 0 |
| Binary replaced out of band | — | retained | 0 |
| Another CNI config on the node still names `ferrum-cni` | removed | retained (shared, still referenced) | 0 |
| The configuration directory could not be fully scanned | removed | retained (references unprovable) | 0 |
| Manifest names a different conflist or binary | removed | retained (evidence not bound to these files) | 0 |

Removal order is always conflist first, then binary: the reverse would leave a chain pointing at a missing plugin, which fails every ADD.

`/opt/cni/bin/ferrum-cni` is a **shared** executable. Another Ferrum release, or an operator-authored configuration, can chain to the same file, so clearing this release's conflist says nothing on its own. Before the binary is removed, cleanup rescans `/etc/cni/net.d/` and retains it if any remaining `.conf` / `.conflist` / `.json` still names the `ferrum-cni` plugin type — and also if that scan could not be completed (an unreadable or unparseable neighbour could be such a configuration). Retention costs a stale, inert file; deletion could break a live release, so the unprovable case keeps the binary.

The primary CNI configuration is never read for modification, rewritten, or deleted in any of these paths.

Note that an unreferenced `/opt/cni/bin/ferrum-cni` is inert. A retained binary is reported but does not fail cleanup; a retained **conflist** does, because that is the file that holds the node hostage. A conflist that belongs to a *different* Ferrum release is not a failure — it is not this release's to lift — and `ferrum-cni uninstall` says so explicitly rather than implying the node is clean.

### Ordering, locking, and what the swap checks do not claim

Install publishes in a fixed order, and each step exists to make the *next* failure recoverable:

0. Under the install lock, **preflight the configured target conflist** before any staging, manifest, binary, or target-config write. Absent → proceed. Present → proceed only when it is a bounded regular single-link file opened `O_NOFOLLOW` whose Ferrum ownership marker names **this same owner** (same-owner upgrades across generations are allowed). An unmarked, malformed, oversized, symlinked, non-regular, hard-linked, or differently-owned file is refused with a fixed error and **no** shared side effects. The exact marker and the exact device/inode/length observed here are remembered for step 6.
1. **Find the primary CNI config, build the chained conflist, and serialize it — all before anything shared is touched.** Every one of those steps can fail on input the installer does not control (no primary matching `chainedWith`, a primary that is not an object, an empty plugin list), so none of them may run after the shared manifest or the shared binary has been written.
2. Stage the new binary in `/opt/cni/bin/` under an unguessable `O_EXCL | O_NOFOLLOW` temporary name, hashing the bytes as they are written. The staging sibling is removed on every exit, so nothing shared has changed yet.
3. **Apply the shared-binary rule.** `/opt/cni/bin/ferrum-cni` is shared, and cleanup already refuses to delete it while another `.conf` / `.conflist` / `.json` on the node names `ferrum-cni`; install owes that reference the mirror guarantee and will not swap the bytes out from under it. Republishing byte-identical bytes is not a replacement and is always allowed. Otherwise, if any other configuration still references the plugin — or if the installed object cannot be classified, or the directory cannot be fully scanned — the install is refused with a fixed error and the shared binary and manifest are left byte-identical. (A directory that cannot be scanned therefore blocks a *binary-changing* upgrade; a same-image reinstall is unaffected.)
4. Write the ownership manifest — **before** the shared binary is published — recording the staged digest, plus an *attested* previous digest where one exists (see "Ownership markers" above). From here on, every artifact this install can leave behind, including after a crash at any later step, is provably Ferrum's and therefore removable.
5. Publish the binary with an atomic same-directory `rename`.
6. Write the chained conflist **last**, atomically. The moment that file lands, every pod ADD on the node traverses `ferrum-cni`, so nothing that can fail may still be pending — its bytes were already built in step 1.

**If any step after the preflight fails and the preflight found this owner's previous chain, the installer lifts that chain before returning the error.** This is an availability rule, not tidiness. On a same-owner upgrade the node is already carrying generation N-1 while the replacement pod's rollback watcher is scoped to generation N; an install that dies before publishing N leaves every pod ADD traversing a socket no node-agent will serve, and the watcher correctly reports `never published` and removes nothing. The recovery runs under the same lock and re-proves the chain first: it removes the file only when it is still the exact object the preflight classified — same device/inode/length **and** a marker naming the same owner *and* the same generation. A different owner, or a generation that overtook the run, is retained untouched and logged; so is a chain the recovery could not remove, which is reported as an error because the node is still dependent. The failure itself is always surfaced; the recovery never masks it.

Every mutating step — the whole of `install`, and the whole of `uninstall` — holds an exclusive `flock` on `/etc/cni/net.d/.ferrum-cni-install.lock` first. That is what makes rollback ownership provable rather than probable: a watcher whose budget expired cannot delete anything while an installer still holds the lock, and it re-reads every ownership marker under that lock before deciding.

Within a run, artifacts are opened `O_NOFOLLOW`, classified against the open handle (regular file, single link, plausible size), read with a hard byte cap that does not trust the pre-read length, and hashed through that same handle — so the digest that authorizes a removal is the digest of the object being removed. Removal re-opens the path `O_NOFOLLOW` and refuses unless the device/inode still matches the object the evidence came from.

What this does **not** claim: the final `unlink` is still by pathname. The lock removes that race between Ferrum's own processes, and the identity re-check refuses every swap that lands before it, but against a third party with write access to a root-owned host CNI directory the window is narrowed rather than closed. Anyone with write access there can already replace the primary CNI configuration outright.

### Automatic rollback when the node-agent never becomes ready

`nodeAgent.cni.rollback.enabled` (default `true`) adds the `ferrum-cni rollback-watch` native sidecar to the node-agent pod. The run has two phases, and the split is load-bearing.

**Phase 1 — publication.** The watcher is a native sidecar, so it starts *before* the installer init container. A readiness budget that started at container start could therefore expire while the installer was still working, delete this generation's state, and then watch the installer publish a conflist that nothing was left to remove — manufacturing exactly the stranded chain the watcher exists to prevent. So the watcher first polls until the generated conflist is on disk carrying **this** owner and generation. That file is written last and atomically, so its presence is the only observable proof that the install completed and the node now depends on the node-agent.

If that never happens within `publishTimeoutSeconds` (default 300), the watcher reports `never published`, removes nothing, and exits non-zero. An installer that never published a chain never created a node-wide dependency *of its own*, so there is nothing for this watcher to roll back — the visible failure belongs to the installer container. The previous generation's chain is not left to this watcher either: a failed same-owner upgrade lifts the chain it found on the installer's own error path, under the same lock (see "Ordering, locking, and what the swap checks do not claim" above). Without that, a generation-N watcher would sit out its publish budget and report `never published` while generation N-1's chain still routed every pod ADD through a socket nothing was going to answer.

Nothing but publication can end phase 1. In particular CNI STATUS is **not** probed before the conflist appears: the socket path is node-scoped and outlives any one install, so a still-running previous node-agent generation can answer `Ok` for a chain this generation has not written yet. Reading that as readiness would return `Ready`, park the watcher for the lifetime of the pod, and leave the rollback permanently disarmed while the installer went on to publish — the exact failure the two-phase split exists to prevent. (Regression pin: `a_status_probe_before_publication_can_never_disarm_the_rollback` in `tests/integration/cni_tests.rs`.)

**Phase 2 — readiness.** Only now does `readyTimeoutSeconds` (default 300) start, and only now is CNI STATUS probed at all, every `pollIntervalSeconds` (default 5).

- **STATUS answers `Ok` at least once** → artifacts are retained for the lifetime of the pod and the watcher parks. A node-agent that fails *later* is deliberately not unchained: it was proven usable, so the pods that depend on its capture are expected to stay enrolled.
- **STATUS never answers `Ok`** → the watcher runs the generation-scoped cleanup and exits non-zero. The container then shows `CrashLoopBackOff`, the pod stays not-Ready, and the failure is visible in `kubectl describe` and the container log.

The outcome it reports is the outcome that actually happened, not a blanket "rolled back":

| Outcome | What is true afterwards | Exit |
|---|---|---|
| `Ready` | STATUS answered; the chain stays for this pod's lifetime | parks |
| never published | this generation never chained the node; nothing removed | **1** |
| rolled back | the chained conflist is gone; pod creation no longer depends on the node-agent | **1** |
| superseded | a newer generation owns the artifacts; **nothing was removed** and the chain is still in place | **1** |
| incomplete | cleanup ran and the chained conflist is **still there**; the node is still dependent | **1** |

Only the "rolled back" line claims the dependency was lifted. A superseded run and an incomplete run both say so plainly instead.

Time decides only *when* to act. *What* may be removed is decided by the markers: the watcher pins both the owner and its own pod UID as the generation, so an install that was overtaken by a newer rollout reports `retained-other-generation` and deletes nothing. Cleanup additionally takes the node lifecycle lock for its whole run, so it cannot interleave with a still-running installer at all.

After a rollback the chain is **not** reinstalled by a container restart — init containers do not re-run. Recreate the node-agent pod (`kubectl delete pod`, or roll the DaemonSet) once the underlying failure is fixed.

Set `nodeAgent.cni.rollback.enabled=false` on clusters older than Kubernetes 1.29 (no native sidecar support) or where you would rather keep a broken install for inspection. The uninstall path is unaffected by this setting.

### Uninstall (`helm uninstall`)

`nodeAgent.cni.uninstall.enabled` (default `true`) renders two `pre-delete` hooks plus the release-owned identity they run as:

| Resource | Kind of resource | Deletion policy | Role |
|---|---|---|---|
| `ferrum-mesh-cni-cleanup` (ServiceAccount) | ordinary release resource | removed by the normal uninstall sweep | No Role, no binding, token not mounted. |
| `ferrum-mesh-cni-cleanup-wait` (ServiceAccount + Role + RoleBinding) | ordinary release resources | removed by the normal uninstall sweep | `get` + `delete` on exactly one DaemonSet, by name, in the release namespace, and `get` on its status. Nothing else. |
| `ferrum-mesh-cni-cleanup` (DaemonSet) | `pre-delete` hook, weight 0 | `before-hook-creation` **only** | Runs `ferrum-cni uninstall` on every node. Deleted by the wait Job, not by Helm. |
| `ferrum-mesh-cni-cleanup-wait` (Job) | `pre-delete` hook, weight 10 | `before-hook-creation,hook-succeeded` | Runs `ferrum-cni await-cleanup`: blocks until every cleanup pod is Ready, then deletes the cleanup DaemonSet and confirms it is gone. |

**Why identity and RBAC are not hook resources.** Helm runs a phase's hooks in weight order, and on **Helm 3.19+ and Helm v4** a later hook's failure also deletes the earlier ones that carry `hook-delete-policy: hook-succeeded` — `deleteHooksByPolicy(executingHooks[0:i], HookSucceeded, ...)` on the failure path of `execHook` in `pkg/action/hooks.go`. (Helm 3.18 and older do not: `execHook` there deletes only the *failing* hook, by its `hook-failed` policy, and reaches the `hook-succeeded` sweep only once every hook in the phase succeeded. The rule below is written for the stricter, newer behaviour so the chart is correct on both.) Held as hook resources, the cleanup ServiceAccounts and RBAC would therefore be destroyed by exactly the failure that makes a retry necessary: the failed DaemonSet's pods would be running against a ServiceAccount that no longer existed, and the next `helm uninstall` would have to recreate the identity before any cleanup pod could be admitted. As ordinary release resources they are created at install time and removed only by the normal uninstall sweep, which runs *after* the pre-delete phase has succeeded — so they are present for the first attempt, still present after a failed one, and gone once the release is really deleted.

**Why the DaemonSet deletes itself through the wait Job.** Helm's hook wait only watches `Job` and `Pod` kinds, so a hook DaemonSet is "succeeded" the instant it is created. A `hook-succeeded` policy on it would therefore delete it immediately — before its pods had cleaned anything — and would additionally delete it on the failure path above, taking the pods and their logs with it. Instead the DaemonSet carries `before-hook-creation` only, and the wait Job removes it once every node has reported success, using foreground propagation and refusing to report success until the API server no longer serves the object. That is a stronger guarantee than the policy would have given: it proves no cleanup pod is still running anywhere before `helm uninstall` is allowed to delete the node-agent.

- **A DaemonSet, not a Job**, because cleanup must happen on every node that ever ran the installer. A Job runs on one node and would silently strand the rest of a multi-node cluster. Each cleanup pod becomes Ready only after `ferrum-cni uninstall` succeeded on *its* node: the container publishes a readiness marker that its `exec` readiness probe (`ferrum-cni uninstall-status`) reads, then holds.
- **Readiness belongs to the current run.** The marker lives in an `emptyDir`, which survives a container restart, so a marker left by an earlier failed start would make the probe pass for work the current invocation has not done. Every `ferrum-cni uninstall` therefore retracts any pre-existing marker *before* touching the node, and publishes a new one only after its own cleanup succeeded. Retraction never follows a symlink and never deletes anything that is not a plain regular file: a symlink, a directory, or any other object at the marker path is refused, and the container exits non-zero rather than publishing readiness through a file it does not own. The publish itself is an atomic `O_EXCL | O_NOFOLLOW` write-and-rename, and the probe accepts only a regular file, so a planted link is never readiness.
- **Plus a wait Job**, because Helm's hook wait only watches `Job` and `Pod` kinds. A hook DaemonSet on its own is created and then left behind — the release, including the node-agent and its socket, could be deleted while cleanup pods were still starting. The Job polls the DaemonSet's ready count and fails after `nodeAgent.cni.uninstall.timeoutSeconds` (default 240) with an "N of M nodes" diagnostic. That value is one shared end-to-end budget for both the readiness wait and the foreground DaemonSet deletion that follows it; it is not restarted between phases. Keep it inside `helm uninstall --timeout` (default 5m) or Helm gives up first and you lose the diagnostic.
- **`pre-delete` only.** `helm upgrade` and `helm rollback` do not fire pre-delete hooks, so a normal rolling pod replacement never removes CNI state that is still required. Upgrades re-run the installer, which is idempotent and rewrites the chain in place.
- **Narrow privileges.** The cleanup pods do pure host-filesystem work, so they get no API access at all (`automountServiceAccountToken: false`), run with `readOnlyRootFilesystem: true` and all capabilities dropped, and mount only the two host CNI directories plus a scratch `emptyDir`. Only the wait Job talks to the API, and it runs as non-root with the named-object Role above: `get` and `delete` on the one DaemonSet it manages, `get` on that DaemonSet's status, and nothing else. There is no `list` and no `watch` — neither can be restricted by `resourceNames` — and no create, update or patch anywhere.
- **`hostNetwork: true` on both.** This is correctness, not tuning. Cleanup runs precisely when a chained `ferrum-cni` is on the node and its socket is about to disappear — and a chained ADD fails closed. A cleanup pod that needed its own CNI sandbox would be stuck in `ContainerCreating` behind the very chain it exists to remove, so the hook would deadlock on every node where it matters. Pods with `hostNetwork: true` skip CNI ADD entirely, exactly like the node-agent DaemonSet they clean up after. The wait Job reaches the API server through `KUBERNETES_SERVICE_HOST` (an IP), so it needs no cluster DNS and keeps `dnsPolicy: Default`.
- **Completion is controller-observed and non-vacuous.** The wait Job treats the DaemonSet as finished only once `status.observedGeneration` has caught up with `metadata.generation`; a status carrying no observed generation counts as *unobserved*, never as observed-and-idle. An all-zero `0/0` status additionally has to persist for 15 s before it is classified as "this DaemonSet scheduled onto no node", so a freshly created DaemonSet's initial snapshot can never be mistaken for completion. A genuine zero is still a **failure**, not vacuous success: the Job retains the DaemonSet and blocks release deletion because no cleanup pod proved that any node's chained CNI configuration was removed.
- **Scoped removal.** The hook passes `EXPECTED_OWNER` (this release) and no generation, so whichever revision is on the node is removed; another release's artifacts are left alone and reported as such.

Failure is loud on purpose, and recoverable by construction. A cleanup container that cannot finish exits non-zero, its pod never goes Ready, the wait Job times out, and `helm uninstall` fails. What survives that failure is chosen deliberately, not assumed: the cleanup DaemonSet carries no `hook-succeeded` policy, so Helm's failure path leaves it, its pods and its logs alone (`kubectl -n <ns> logs daemonset/ferrum-mesh-cni-cleanup`), and the ServiceAccounts, Role and RoleBinding are release resources that a failed pre-delete phase never reaches. Recovery is therefore just `helm uninstall` again: `before-hook-creation` replaces the DaemonSet and the failed wait Job, the surviving identity admits the new pods immediately, and the same wait runs against the same budget. Do not add `hook-succeeded` to the DaemonSet — it would delete the evidence and the retry path at the same time.

The hook tolerates all taints by default (`nodeAgent.cni.uninstall.tolerations`) so it reaches every node the node-agent could run on. A node that is cordoned, `NotReady`, or otherwise unschedulable cannot be cleaned by the hook — the uninstall will time out and report failure. That is intentional: the alternative is declaring success while a live node keeps a chained conflist pointing at a socket that is about to disappear. Clean such nodes with the manual steps below, then re-run the uninstall (or set `nodeAgent.cni.uninstall.enabled=false` to skip the hook entirely and accept manual cleanup).

### Recovering a node

Symptom: pods on a node stick in `ContainerCreating` with a CNI error mentioning `ferrum-cni`.

1. Confirm the chain is Ferrum's and see who owns it:
   ```bash
   cat /etc/cni/net.d/00-ferrum.conflist
   cat /etc/cni/net.d/.ferrum-cni-owned.marker
   ```
2. Remove the chain. Preferred, because it validates ownership before touching anything:
   ```bash
   HOST_CONF_DIR=/etc/cni/net.d HOST_BIN_DIR=/opt/cni/bin \
   CONF_FILE_NAME=00-ferrum.conflist \
   ferrum-cni uninstall
   ```
   If the binary is not usable, delete **only** the generated conflist by hand:
   ```bash
   rm /etc/cni/net.d/00-ferrum.conflist
   ```
   The primary CNI configuration it chained behind was never modified, so nothing else needs repairing; kubelet picks the primary config up again on the next ADD.
3. Fix the node-agent (see the diagnostics table above and `ferrum_node_agent_cni_socket_lifecycle_total`), then recreate the node-agent pod to reinstall the chain.

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
- **Enabled but UDS unreachable.** If the listener fails to bind (permission error on the parent dir or another live generation holds the ownership lock), the node-agent logs `error!` and continues running with the watcher path active. Stale socket files from crashed owners are recovered only after the new process acquires that lock. The CNI binary on the host then fails **every** kubelet ADD on that node with `IpcFailed`, so new pods stick in `ContainerCreating` — the watcher path still reconciles pods that already have a sandbox, but it cannot create one. If this happens during initial pod startup the rollback watcher removes the chain once its readiness budget expires; if it happens after the node-agent was once ready, recovery is manual ("Recovering a node").
- **CNI plugin installed but node-agent not running.** Same effect as above, and the watcher path is irrelevant because the node-agent process is absent. If the pod never became ready in the first place, the rollback watcher unchains the node automatically.
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
      "ferrum": {
        "socketPath": "/var/run/ferrum/node-agent-cni.sock",
        "managedBy": "ferrum-edge",
        "owner": "ferrum/ferrum-mesh",
        "generation": "8f1c1a0e-...-pod-uid"
      } }
  ]
}
```

The `managedBy` / `owner` / `generation` keys are the ownership markers described below; the plugin itself ignores them on the request path.

The generated `name` is preserved from the matched primary CNI config, so it will usually be the primary network name rather than a Ferrum-specific constant.

The chart writes the file at a numeric prefix (`00-`) so kubelet selects the generated chain before a typical `10-...` primary config file. Inside the generated file, the primary plugin still runs before `ferrum-cni`. Operators with custom primary prefixes should choose a generated filename that sorts before the runtime-selected primary config.

### Observability

`/metrics` exposes `ferrum_node_agent_cni_calls_total{verb,outcome}` with closed labels (`verb ∈ {add,del,check,status,gc}`, `outcome ∈ {success,rejected,error}`). Bounded cardinality (15 series at most). Reset on process restart. Operators use this to confirm the CNI plugin is the primary enrollment path (`success` rate climbs) versus the watcher fallback (`success` rate stays at 0 even though pods are enrolled), and to observe STATUS readiness and GC reconciliation outcomes.

Socket lifecycle failures use
`ferrum_node_agent_cni_socket_lifecycle_total{reason}` with the closed reasons
`ownership_conflict`, `ownership_io_error`, `stale_socket_cleanup_error`,
`handoff_identity_error`, `handoff_publication_error`, and
`shutdown_cleanup_error`. The corresponding structured log carries the same
`reason`; an ownership conflict is an explicit startup refusal, not stale-file
recovery.

### Lifecycle coverage and remaining gaps

Delivered (issue #3609):

- **Uninstall.** `ferrum-cni uninstall`, plus the `pre-delete` hook DaemonSet that runs it on every node before the socket disappears.
- **Rollback.** `ferrum-cni rollback-watch` removes an install that never reached CNI readiness, scoped by ownership and generation, with the readiness budget gated on this generation's own publication.
- **Install verification.** The rollback watcher's STATUS poll *is* the post-install probe: an install whose plugin never answers is undone rather than left in place. The ownership manifest additionally records the digest of the binary that was installed, so an out-of-band replacement is detectable (and blocks removal of that binary). Install also fail-closes under the lifecycle lock before overwriting an existing target conflist unless that file's Ferrum marker names this same owner.
- **In-place upgrade.** See below.
- **Hosted evidence.** External Rust integration coverage in `tests/integration/cni_tests.rs` (`install_lifecycle`, including crash-loop ADD fail-closed, ownership mismatch, repeated cleanup, and upgrade ordering) plus the existing CI Helm render/static contract assertions, plus the privileged live suite `tests/k8s/cni_lifecycle_live/run.sh` (workflow `.github/workflows/cni-lifecycle-live.yml`): live kind install → fail-closed pod creation → rollback recovery → idempotent uninstall → chart cleanup graph failure/retry → full-chart `helm install` / `helm uninstall` under the cluster's real primary CNI.

**In-place upgrade.** A re-run of the installer is an upgrade, and the semantics are now explicit rather than incidental:

- The new binary is staged in the destination directory and published by an atomic same-directory `rename`. The installed file is never truncated or written through, so an already-exec'd `ferrum-cni` keeps a valid inode and finishes its RPC forward against the binary it started with — there is no torn-binary or `ETXTBSY` window.
- When the staged bytes are byte-identical to what is already installed — the routine `helm upgrade` with an unchanged image — the rename is **skipped entirely**. The common upgrade therefore performs no binary swap at all, so no in-flight plugin can straddle one.
- The manifest is rewritten before the swap and records both the digest being published and the digest being replaced, so a crash between those two steps still leaves whichever binary is on disk provably removable.
- The conflist is re-stamped with the new generation last, so kubelet's next ADD resolves the new inode through a fresh `exec`.

What remains true, and is a property of POSIX rather than a gap Ferrum can close: a plugin process already `exec`'d from the previous inode runs the previous code until it exits. Because the RPC contract is forward-compatible within a release and the forward is a single sub-second call, that is a coordination *cost* rather than an upgrade barrier — and the skip-if-identical rule removes it from the common case. There is no cross-process handshake that would make an already-running plugin adopt new code, so none is claimed.

**Post-readiness failure recovery boundary (by design).** Automatic rollback is a *never-ready* path only. The moment CNI STATUS answers `Ok` for this generation, the watcher retains the chain for the lifetime of the pod and never silently unchains a later crash-loop. That is the capture-race posture: a node that was once enrolled stays dependent until an operator (or `helm uninstall`) removes the chain. Recovery after that boundary is the manual path in "Recovering a node" — delete the Ferrum-owned conflist (preferably via `ferrum-cni uninstall`), fix the node-agent, recreate the pod to reinstall. The Rust suite pins the retain-after-ready half (`rollback_watch_retains_artifacts_once_readiness_is_observed`); the live suite pins the never-ready and uninstall halves.

Still deferred / unclaimed operational gaps:

- **Admission-time validation of pod CNI metadata.**
- **Automatic rollback for a node-agent that fails after it was once ready.** Deliberately not implemented (see the boundary above); recovery is the manual path in "Recovering a node".
