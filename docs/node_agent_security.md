# Node Agent Security Posture

`FERRUM_MODE=node_agent` is the only Ferrum mode that loads eBPF programs and
attaches them to pod cgroups on the host kernel. It runs as a privileged
DaemonSet next to (or under) the mesh proxy, so its blast radius is the
node, not just a single container. This document is the reference for the
Linux capabilities, mounts, syscalls, seccomp/AppArmor profiles, and
Kubernetes pod-spec controls that the agent actually requires — and the
ones it does NOT, so operators can lock it down.

The kernel-facing operations and capability requirements documented here
trace to the code paths under [`src/modes/node_agent.rs`](../src/modes/node_agent.rs)
and [`src/ebpf/`](../src/ebpf/). For the capture contract surface
(BPF maps, ports, ABI) see [`docs/node_agent.md`](node_agent.md). For
mesh-mode topology see [`docs/mesh.md`](mesh.md).

## Table of Contents

1. [Threat model](#threat-model)
2. [Required Linux capabilities](#required-linux-capabilities)
3. [Required mounts and host access](#required-mounts-and-host-access)
4. [Least-privilege pod spec example](#least-privilege-pod-spec-example)
5. [Seccomp profile](#seccomp-profile)
6. [AppArmor profile](#apparmor-profile)
7. [Pod Security Standards compatibility](#pod-security-standards-compatibility)
8. [Network exposure and NetworkPolicy](#network-exposure-and-networkpolicy)
9. [CNI install lifecycle](#cni-install-lifecycle)
10. [Audit and logging](#audit-and-logging)
11. [Compromise containment](#compromise-containment)
12. [Threat-by-threat checklist](#threat-by-threat-checklist)

## Threat model

### What the node agent does

- Loads a static eBPF object (`ferrum-ebpf.o`) compiled at build time, attaches
  the programs to:
  - The **per-pod cgroup v2** for every enrolled pod on the node
    (`connect4`, `connect6`, `getpeername4`, `getpeername6` — `cgroup_sock_addr`).
  - The **host-side veth ingress/egress** of every enrolled pod
    (`ferrum_tc_inbound` — `sched_cls` classifier on tc ingress/egress).
  - When `FERRUM_NODE_AGENT_INGRESS_REDIRECT_IFACES` is set, one additional
    `sched_cls` classifier (`ferrum_tc_ingress_redirect`) on the tc **ingress**
    hook of each named node capture interface, plus a Ferrum-owned policy route
    (`ip rule` priority 101 / table 33134, per family). It uses
    `bpf_sk_assign()` to steer inbound TCP for enrolled workloads into the
    proxy's transparent inbound **capture** listener — never the HBONE
    listener, which terminates authenticated H2 CONNECT over mesh mTLS. It
    rewrites no addresses and adds no capability beyond the `CAP_NET_ADMIN` the
    existing tc attachments already require. Unset (the default) leaves it
    uninstalled and the kernel program inert. Redirection is scoped per packet
    to an enrolled, opted-in pod address on a declared inbound port (fragments
    excluded), so it cannot capture unenrolled traffic; an in-scope packet with
    no resolvable capture-listener socket is dropped rather than delivered.
    Captured plaintext is then admitted only where the live PeerAuthentication
    posture **of the exact destination workload** allows it — `STRICT` still
    requires verified mesh transport — and only to a workload in this
    NodeWaypoint's authorized capture destination inventory, on a port that
    workload declares, after the L4 `mesh_authz` chain. That inventory (and the
    PeerAuthentication candidates applicable to it) is resolved control-plane
    side under the CP namespace scope and the bearer `ns` claim, so a
    cross-namespace enrolled pod's own `STRICT` policy is enforced while an
    unauthorized namespace contributes nothing; a missing inventory refuses the
    connection rather than defaulting `PERMISSIVE`.
  - The **cgroup root** for global socket-ops telemetry
    (`ferrum_sock_ops` — `sock_ops`, attached once at startup).
- Pins SOCK_OPS event and stats maps into `/sys/fs/bpf/ferrum/` so the
  co-located mesh proxy can open them by path. No additional IPC.
- Watches `pods` (`get`/`list`/`watch`) and, when proving the optional ingress
  redirect topology, maintains one bounded cluster-wide `nodes`
  (`list`/`watch`) cache via the Kubernetes API using the in-cluster
  ServiceAccount token. The pod watcher is filtered server-side to
  `spec.nodeName=$FERRUM_NODE_AGENT_NODE_NAME`; the projected Node cache retains
  only names, PodCIDRs, the Ready truth value, and InternalIP route evidence.
- On kernels that do not support cgroup/sockaddr BPF (< 5.7 or no cgroup v2),
  falls back to `iptables` / `ip6tables` rules invoked via `sh -c`
  ([`handle_fallback` in `src/modes/node_agent.rs`](../src/modes/node_agent.rs)).
- Optionally exposes a read-only admin listener for `/metrics` and `/health`
  (loopback-only by default — see [`docs/node_agent.md`](node_agent.md)).

### What it can read or modify

- **Read**: every pod's metadata and bounded Node PodCIDR/InternalIP topology via
  the API server (within ClusterRole RBAC); every cgroup path under
  `/sys/fs/cgroup`; host route state under `/proc/net/`; host network interface
  state under `/sys/class/net/`; every PID's net namespace info under
  `/proc/{pid}/net/if_inet6` (because of `hostPID: true`).
- **Modify**: BPF maps (`FERRUM_POD_IPS`, `FERRUM_POD_IPS6`, `FERRUM_BYPASS_UIDS`,
  `FERRUM_CIDR_*`, `FERRUM_PORT_EXCLUDE`, `FERRUM_INCLUDE_PORTS`,
  `FERRUM_CAPTURE_CONFIG`, `FERRUM_ORIG_DST4/6`, `FERRUM_SOCK_OPS_*`);
  cgroup-attached BPF program list; tc qdisc/filter list on host veth
  interfaces; on fallback, iptables/ip6tables NAT rules on the host.
- **Cannot read** (without additional capabilities NOT requested):
  pod memory, pod filesystems, container runtime sockets, host /etc, host
  /var/lib/docker, kernel keyring, dmesg.

### Blast radius if compromised

A compromised node agent can:

- Redirect outbound traffic from any pod on the node to a chosen
  destination by rewriting `FERRUM_POD_IPS` / `FERRUM_POD_IPS6` /
  `FERRUM_CAPTURE_CONFIG` or
  by attaching attacker-controlled cgroup programs (subject to having loaded
  programs first — see capability discussion).
- Attach arbitrary tc programs to host veth interfaces (within the
  `CAP_NET_ADMIN` boundary) — observe / drop / modify packets on the wire
  for any pod on the node.
- Read every pod's metadata from the API server within its ClusterRole.
- Pollute pinned BPF maps under `/sys/fs/bpf/ferrum/` so the
  co-located mesh proxy ingests forged telemetry.

A compromised node agent **cannot** (without operator misconfiguration):

- Read or write other pods' filesystems, container memory, or root
  filesystem (no privileged mode, no container runtime socket mount,
  `readOnlyRootFilesystem: true`).
- Write to the Kubernetes API beyond the read-only `pods`/`nodes` ClusterRole.
- Mutate other nodes' state (the watcher is field-scoped to its own node).
- Escalate to host root via container escape unless the kernel itself has
  a separate vulnerability — running as UID 0 inside the container is
  required for BPF attach, but with `allowPrivilegeEscalation: false`
  there is no setuid path out.

## Required Linux capabilities

The node agent runs as UID 0 inside the container because the kernel
checks capabilities via the effective UID's credentials. Every requested
capability traces to a specific kernel API used by the code.

| Capability | Required for | Kernel API | Code site |
|---|---|---|---|
| `CAP_BPF` | Loading BPF programs and creating BPF maps. Available on kernel **≥ 5.8** — split out of `CAP_SYS_ADMIN`. | `bpf(BPF_PROG_LOAD)`, `bpf(BPF_MAP_CREATE)`, `bpf(BPF_*_ELEM)` | `EbpfLoader::load()` in [`src/ebpf/loader.rs`](../src/ebpf/loader.rs); map updates in [`src/ebpf/maps.rs`](../src/ebpf/maps.rs) |
| `CAP_NET_ADMIN` | Attaching BPF programs to cgroups (`BPF_PROG_ATTACH` for `BPF_CGROUP_INET_*`/`BPF_CGROUP_SOCK_OPS` types); attaching tc classifiers (incl. the opt-in `ferrum_tc_ingress_redirect` on node capture interfaces); managing host veth qdiscs; the Ferrum-owned `ip rule`/`ip route` policy route for redirect local delivery; binding the single `IP_TRANSPARENT` inbound capture listener (no other listener is transparent); iptables/ip6tables NAT rules on the fallback path. | `bpf(BPF_PROG_ATTACH)` for cgroup hooks; `tc` netlink (`RTM_NEWTFILTER`); `iptables-restore`/`ip6tables` syscalls. | `attach_cgroup`, `attach_tc`, `attach_sock_ops` in [`src/ebpf/loader.rs`](../src/ebpf/loader.rs); `execute_iptables_commands` in [`src/modes/node_agent.rs`](../src/modes/node_agent.rs) |
| `CAP_PERFMON` | Reading BPF program / map info from the kernel (BTF, prog info, map info) on kernel **≥ 5.8**. Split out of `CAP_SYS_ADMIN`. | `bpf(BPF_OBJ_GET_INFO_BY_FD)`, `bpf(BPF_BTF_LOAD)` | `aya::Ebpf::load` BTF resolution; map iteration in [`src/ebpf/loader.rs`](../src/ebpf/loader.rs) |
| `CAP_SYS_ADMIN` | Kernel-backcompat for BPF on kernel **< 5.8**. Also required in `node_waypoint` mode on every supported kernel because the agent enters pod network namespaces with `setns()` to resolve host-side veth peers before tc attachment. The chart drops `SYS_ADMIN` for `local_pod` mode on modern kernels but always adds it for `nodeAgent.proxyMode=node_waypoint`. | Older-kernel BPF operations; `setns(CLONE_NEWNET)` for pod-netns veth discovery. | Same as `CAP_BPF` / `CAP_PERFMON`; `discover_host_veth_for_pod` in [`src/ebpf/veth.rs`](../src/ebpf/veth.rs) |
| `CAP_SYS_PTRACE` | NodeWaypoint ambient proxy only. With `hostPID: true`, Linux still applies `ptrace_may_access` checks to `/proc/{pid}/ns/net`; workloads running with different UIDs or dumpability can otherwise return `EACCES` before the proxy can enter the pod netns. This is not used for `PTRACE_ATTACH`. | `stat`/`open` of `/proc/{pid}/ns/net` for enrolled pod PIDs. | `netns_inode_for_cgroup` and `NetnsGuard::enter` in [`src/proxy/netns_capture.rs`](../src/proxy/netns_capture.rs) |

When `nodeAgent.proxyMode=node_waypoint`, the ambient mesh proxy is part of the
same capture data path. The chart also grants that proxy `CAP_BPF`,
`CAP_PERFMON`, `CAP_SYS_ADMIN`, and `CAP_SYS_PTRACE`: it opens the
node-agent-pinned BPF maps by path, reads SOCK_OPS/orig-dst records, resolves
registered pod PIDs through host `/proc`, and enters each enrolled pod's
network namespace with `setns(CLONE_NEWNET)` to bind the pod-loopback capture
listener.
Those extra proxy permissions are not rendered for regular ambient iptables
mode.

`CAP_SYS_PTRACE` is intentionally scoped to the NodeWaypoint ambient proxy, not
the node-agent DaemonSet. It is broader than the Ferrum code path that uses it:
Ferrum does not call `ptrace(2)`, but a compromised proxy process with that
capability should be treated as capable of same-node process inspection unless
an LSM profile blocks those syscalls.

### Host-network UDP capture drops the setns privilege set (issue #3288)

Ambient UDP capture has two placements, and they have materially different
privilege footprints:

| Placement | `FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED` | Proxy capabilities | Host access |
|---|---|---|---|
| Per-pod-netns producer (default) | `false` | `NET_ADMIN`, `NET_RAW`, `SYS_ADMIN`, `SYS_PTRACE` | `hostNetwork`, `hostPID`, host cgroup (ro), registry hostPath |
| Host-network capture | `true` | `NET_ADMIN`, `NET_RAW` | `hostNetwork`, host cgroup (ro), registry hostPath |

The host placement installs its `mangle` rules and binds its transparent socket
in the proxy's own namespace, so it calls no `setns(CLONE_NEWNET)` and never opens
another workload's `/proc/{pid}/ns/net`. That removes both the `ptrace_may_access`
requirement and `hostPID` from the ambient DaemonSet, which is the main reason to
choose it: it is the UDP capture path available on clusters whose Pod Security
posture will not grant `SYS_ADMIN`/`SYS_PTRACE`. The chart derives this
automatically — enabling the placement narrows the rendered capabilities rather
than adding to them.

The narrowing happens only after the enforced UDP placement migration completes.
An explicit `cleanup` release from `pod-netns` or `disabled` to `host-netns`
retains `hostPID`, `SYS_ADMIN`, and `SYS_PTRACE` so it can retire exact
Ferrum-owned rules inside every predecessor pod netns. The incoming host
producer does not start in that release. `finalize` is admitted only after the
node-local durable proof exists, and only then does the chart remove the setns
privilege set. See the [Ambient UDP migration procedure](mesh.md#ambient-udp-placement-migration-enforced-hard-upgrade-guard).

Once that migration has completed, a node with no node-local durable record —
one that joined the cluster afterwards, or whose registry directory was
recreated by a reboot — adopts the placement from the chart-rendered
`FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED` attestation, which the chart
derives only from the already-installed placement ConfigMap. That widens no
privilege: such a node still renders the narrowed host-placement capability set,
and the attestation is consulted only when the durable record is absent, so it
can never authorize an in-place flip on a running node. A
`.udp-placement-quarantined` tombstone in the registry directory refuses every
absent-state bootstrap outright, which is what makes the corrupt-ownership
repair procedure machine-enforced rather than advisory.

What it does NOT reduce is `CAP_NET_ADMIN`: the path still writes `mangle` chains,
an `ip rule`, and an `ip route` in the host namespace, and still binds
`IP_TRANSPARENT` sockets. The chart also retains the ambient container's existing
`CAP_NET_RAW`; the host UDP implementation itself adds no raw-socket operation.
Treat a compromised proxy in this placement as able to rewrite host netfilter
state, exactly as in the default placement.

Dropping `hostPID` means the pod's own `/proc` view is unavailable, so interface
resolution falls through to the host route table for **both** address families
(`/proc/net/route` and `/proc/net/ipv6_route`). That parsing is treated as
hostile input: bounded reads, strict field decoding, and only an unambiguous
`RTF_UP` host route (`/32` or `/128`), followed by a sysfs check that the device
has a distinct non-zero peer `iflink` and is not a bridge. A broader route or a
self-linked device is not ownership evidence and is refused; two devices
claiming the host route also resolve to nothing. A crafted or degenerate route
table can therefore make a pod *unresolvable* (refused, egress stays closed) but
never deliberately select a covering shared device.

Two properties bound the blast radius of the rules it installs. It emits **no
`mangle OUTPUT` chain**, so the node's own traffic (kubelet, CNI, DNS, every
`hostNetwork` pod) is structurally outside the capture set rather than excluded by
a filter. And every capture rule is scoped `-i <one enrolled pod's host-side
interface>`, with the interface name validated before it reaches the generated
`sh -c` script: only `[A-Za-z0-9._-]` up to the 15-character kernel limit, no
leading `-`, and no `+` (which `iptables` reads as a **prefix wildcard** and would
silently widen capture to every interface sharing a prefix). A registry entry that
resolves to a rejected name fails the whole plan rather than being skipped, so a
corrupt or hostile entry cannot yield a partially-scoped ruleset.

### Capabilities deliberately NOT requested

- **`CAP_SYS_RESOURCE`** — `raise_fd_limit()` in [`src/main.rs`](../src/main.rs)
  raises only the soft FD cap (via `setrlimit(RLIMIT_NOFILE)`); the hard cap
  is set by the operator via `LimitNOFILE=` (systemd) or `--ulimit nofile=`
  (Docker / K8s). Raising the soft cap up to the hard cap is permitted to
  any process and does not require `CAP_SYS_RESOURCE`. The code already
  handles `setrlimit` denial gracefully (`warn!` + continue).
- **`CAP_NET_RAW`** — no raw-socket / packet-capture operation in node-agent
  code. (The `ambient` DaemonSet has `CAP_NET_RAW` for its own
  reasons; the node-agent does not.)
- **`CAP_SYS_MODULE`** — BPF programs are not loaded as kernel modules.
- **`privileged: true`** — covers every capability above with the kernel's
  full permission set, defeats seccomp, and grants unrestricted device
  access. None of those are required by the node agent.

## Required mounts and host access

| Mount | Path | Mode | Why required |
|---|---|---|---|
| `bpf-fs` (hostPath) | `/sys/fs/bpf` (default; override via `FERRUM_NODE_AGENT_BPF_FS_PATH`) | rw | Pinned BPF maps must live on bpffs so the mesh proxy can open `/sys/fs/bpf/ferrum/sock_ops_events`, `/sys/fs/bpf/ferrum/sock_ops_stats`, and `/sys/fs/bpf/ferrum/accept_first_byte_sockets` by path ([`src/ebpf/loader.rs::pin_sock_ops_maps`](../src/ebpf/loader.rs)). |
| `cgroup` (hostPath) | `/sys/fs/cgroup` (default; override via `FERRUM_NODE_AGENT_CGROUP_ROOT`) | ro | Opening a cgroup directory FD is required to call `BPF_PROG_ATTACH` against it (`attach_cgroup` in [`src/ebpf/loader.rs`](../src/ebpf/loader.rs)). The directory is mounted read-only; BPF attach uses the FD via the BPF subsystem, not direct cgroup writes. |
| ServiceAccount token | `/var/run/secrets/kubernetes.io/serviceaccount/` | ro | Automatically projected by the kubelet. Consumed by `kube::Config::incluster()` ([`build_node_agent_kube_client` in `src/modes/node_agent.rs`](../src/modes/node_agent.rs)) to authenticate the `pods`/`nodes` watcher to the API server. Operators should prefer a **projected** token with a short `expirationSeconds` (the kubelet handles rotation) over the legacy long-lived Secret token. |
| `/proc` | implicit via `hostPID: true` | ro | Veth discovery reads `/proc/{pid}/net/if_inet6` ([`src/ebpf/veth.rs`](../src/ebpf/veth.rs)) to find the host-side veth ifindex for each enrolled pod. Without `hostPID`, the container's `/proc` only shows its own PIDs and cannot resolve pod-PID-to-veth. |

In NodeWaypoint topology, the ambient proxy mounts the same host bpffs and
cgroup roots read-only and also runs with `hostPID: true`. It does not attach
BPF programs or write cgroups; it needs those views to open pinned maps, find a
live PID in each registry cgroup, and `setns()` into the matching pod network
namespace before publishing `<podRegistryDir>/.ready/<pod_uid>`.

### Mounts deliberately NOT requested

The node agent does **not** need, and the chart does **not** mount:

- `/` (host root) or `/var/lib/docker`, `/var/lib/containerd`, `/run/crio`,
  `/var/run/docker.sock`, `/var/run/containerd/containerd.sock`, or any
  other container runtime socket. Pod metadata is obtained via the
  Kubernetes API, not by talking to the runtime.
- `/etc` (host configuration), `/var/log` (host logs), `/dev` (raw devices),
  `/lib/modules` (kernel modules).
- Any pod's filesystem or volume.

One documented exception, and only when you opt in with
`nodeAgent.cni.enabled=true`: the CNI install lifecycle mounts
`/opt/cni/bin`, `/etc/cni/net.d`, and the socket directory
(`/var/run/ferrum`) read-write. This is a narrow, named carve-out from the
"no `/etc`" rule above — `/etc/cni/net.d` only, never `/etc` itself — and it
is what the installer, the rollback watcher, and the uninstall hook use to
write and remove Ferrum's own plugin binary and chained conflist. See
[CNI install lifecycle](#cni-install-lifecycle) for the ownership rules that
bound what those mounts are allowed to touch.

If you see a fork or downstream chart that adds any of these mounts to
the node-agent DaemonSet, treat it as a red flag and confirm the use
case before merging.

### `hostNetwork: true` and `hostPID: true`

Both are required and are the most powerful pieces of host access the
agent has — they cannot be opted out of without losing function:

- **`hostNetwork: true`**: tc programs are attached on the host-side veth
  by interface name from `/sys/class/net/` ([`src/ebpf/veth.rs`](../src/ebpf/veth.rs)),
  and the pinned BPF map files under `/sys/fs/bpf/ferrum/` are opened by the
  co-located mesh proxy via the same host filesystem view. Without
  `hostNetwork`, the agent cannot see host veths nor coordinate with the
  in-namespace mesh proxy.
- **`hostPID: true`**: see `/proc` mount above. The pod-PID-to-veth lookup
  is the only consumer.

Both flags expose the host's network and PID namespaces inside the
container. Combined with `runAsUser: 0` and `CAP_NET_ADMIN`, the
agent already has the de-facto ability to manipulate host networking
within the seccomp boundary. The pod-spec controls below
(`allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`,
seccomp / AppArmor) limit what the agent can do *beyond* its documented
function if compromised.

## Least-privilege pod spec example

This is the spec the Helm chart in this repository renders for
`nodeAgent.enabled: true` after the tightenings in this commit. Helm values
are kept backward-compatible — every new default below is reversible via
`nodeAgent.security.*` for operators on older kernels or alternative
runtimes.

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ferrum-mesh-node-agent
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: ferrum-mesh-node-agent
  template:
    metadata:
      labels:
        app.kubernetes.io/name: ferrum-mesh-node-agent
      annotations:
        container.apparmor.security.beta.kubernetes.io/ferrum-edge: localhost/ferrum-node-agent
    spec:
      serviceAccountName: ferrum-node-agent
      automountServiceAccountToken: true
      hostPID: true
      hostNetwork: true
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: ferrum-edge
          image: ferrumedge/ferrum-edge:0.9.0-ebpf
          args: ["run"]
          securityContext:
            # Root is required inside the container for BPF cgroup attach;
            # privilege escalation is denied to block setuid escape paths.
            runAsUser: 0
            runAsGroup: 0
            privileged: false
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
              add:
                - BPF              # kernel >= 5.8; covered by SYS_ADMIN on older
                - NET_ADMIN        # cgroup/tc attach, iptables fallback
                - PERFMON          # kernel >= 5.8 BPF info/BTF
                - SYS_ADMIN        # required by node_waypoint setns/veth discovery
          volumeMounts:
            - name: bpf-fs
              mountPath: /sys/fs/bpf
            - name: cgroup
              mountPath: /sys/fs/cgroup
              readOnly: true
            - name: tmp
              mountPath: /tmp
          # Pod must be allowed to write to /tmp for tokio's temporary
          # files; /tmp is an emptyDir so the root FS stays read-only.
          env:
            - name: FERRUM_MODE
              value: "node_agent"
            - name: FERRUM_MESH_CAPTURE_MODE
              value: "ebpf"
            - name: FERRUM_NODE_AGENT_PROXY_MODE
              value: "node_waypoint"
            - name: FERRUM_NODE_AGENT_NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
      volumes:
        - name: bpf-fs
          hostPath:
            path: /sys/fs/bpf
            type: DirectoryOrCreate
        - name: cgroup
          hostPath:
            path: /sys/fs/cgroup
            type: Directory
        - name: tmp
          emptyDir: {}
```

Notes:

- `readOnlyRootFilesystem: true` requires an emptyDir at `/tmp` because
  Rust's `tokio` and `tracing-subscriber` may open temporary files there.
  The chart provisions this automatically when `nodeAgent.security.readOnlyRootFilesystem`
  is true.
- `allowPrivilegeEscalation: false` is safe because the agent never
  exec's a setuid binary. When operators explicitly enable
  `FERRUM_NODE_AGENT_FALLBACK_MODE=iptables` with a custom image that
  includes `/bin/sh` and iptables tools, that fallback inherits the same
  uid/caps and does not need to escalate.
- The AppArmor annotation
  (`container.apparmor.security.beta.kubernetes.io/<container>`) shown
  above is the **deprecated** form — it was removed in Kubernetes 1.31.
  On 1.30+, prefer the GA field form:
  `securityContext.appArmorProfile.{type: Localhost, localhostProfile: ferrum-node-agent}`
  on the pod or container `securityContext`. The annotation form is
  retained in the example for compatibility with clusters older than
  1.30, where the field form is not recognized.

## Seccomp profile

`seccompProfile: { type: RuntimeDefault }` (Docker / containerd default)
**allows** the syscalls the node agent needs:

- `bpf()` — load programs and update maps.
- `setsockopt()` — used indirectly by the in-binary mesh-proxy adjacent
  code paths but not by `node_agent` mode itself.
- `socket()`, `connect()`, `bind()` — Kubernetes client.
- `openat()`, `read()`, `write()`, `mmap()`, `pinning` via `bpf_obj_pin`
  (a flag on the `bpf()` syscall, not a separate syscall).
- `clone3()`, `execve()` — `sh -c "iptables ..."` on the kernel-fallback
  path.

Operators wanting a tighter profile than RuntimeDefault can start from a
copy of the containerd default and explicitly allow:

```jsonc
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {
      // Everything the runtime-default allows plus:
      "names": [
        "bpf",
        "perf_event_open",   // required if BTF parsing falls through to perf
        "setns",             // not used today; pre-allowed for veth/cgroup ns helpers
        "openat", "openat2", "fstatat", "fstat", "readlinkat",
        "execve", "execveat", "clone", "clone3",     // sh -c iptables fallback
        "ioctl",                                      // netlink for tc
        "sendmsg", "recvmsg", "sendto", "recvfrom",  // netlink + kube client
        "epoll_create1", "epoll_ctl", "epoll_pwait",
        "futex", "rseq", "membarrier"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

Two notes on writing custom profiles:

- The `bpf` syscall is the load-bearing one; if a profile omits it, the
  agent will fail to start with a clear error from `EbpfLoader::load`.
- `iptables` invokes `iptables-legacy` or `iptables-nft` depending on the
  host (the agent uses whichever `iptables` resolves to via `sh -c`).
  `nft` paths require additional netlink syscalls that RuntimeDefault
  already permits.

## AppArmor profile

A tightened AppArmor profile that restricts the agent's filesystem
writes to its expected paths. Save as
`/etc/apparmor.d/usr.local.bin.ferrum-node-agent`, load with
`apparmor_parser -r`, and reference via the pod annotation in the spec
above.

```text
#include <tunables/global>

profile ferrum-node-agent /usr/local/bin/ferrum-edge {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Binary and its libs
  /usr/local/bin/ferrum-edge mr,
  /usr/lib/** mr,
  /lib/** mr,
  /etc/ld.so.cache r,

  # ServiceAccount token (projected by kubelet)
  /var/run/secrets/kubernetes.io/serviceaccount/** r,
  /var/run/secrets/tokens/** r,

  # bpffs — read existing pins, write/replace own pins under /ferrum/
  /sys/fs/bpf/ r,
  /sys/fs/bpf/ferrum/ rw,
  /sys/fs/bpf/ferrum/** rw,

  # cgroup v2 — read for attach, no writes (attach uses BPF subsystem fd)
  /sys/fs/cgroup/** r,

  # Kernel/version probes
  /proc/sys/kernel/osrelease r,
  /proc/*/net/if_inet6 r,
  /sys/class/net/ r,
  /sys/class/net/*/ifindex r,

  # tmpfs for tracing scratch
  /tmp/** rw,

  # iptables fallback only
  /usr/sbin/iptables Px,
  /usr/sbin/ip6tables Px,
  /usr/sbin/iptables-* Px,
  /usr/sbin/ip6tables-* Px,
  /bin/sh Px,
  /usr/bin/sh Px,

  # Network + BPF capabilities are still enforced by the kernel cap set
  capability bpf,
  capability net_admin,
  capability perfmon,
  capability sys_admin,
  # Needed only if this profile is reused for the NodeWaypoint ambient proxy.
  capability sys_ptrace,
}
```

Anything not in the profile is denied with an audit log entry, which
makes deviation from the documented surface visible in the host audit
log without breaking the agent on its expected paths.

## Pod Security Standards compatibility

[Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
levels and node-agent compatibility:

- **`restricted`** — **incompatible**. Disallows `CAP_NET_ADMIN`,
  `hostNetwork`, `hostPID`, and `runAsUser: 0`. The node agent needs
  all four. Do not label the namespace `pod-security.kubernetes.io/enforce: restricted`.
- **`baseline`** — **partially compatible.** Baseline allows `CAP_NET_ADMIN`
  and a configurable capability set but **disallows `hostNetwork` and `hostPID`**.
  The node-agent namespace cannot use baseline either.
- **`privileged`** — compatible. This is what most operators end up with
  for any DaemonSet that touches the kernel.

Recommended posture: label the node-agent's namespace
`pod-security.kubernetes.io/enforce: privileged` (which is the K8s default
for system namespaces anyway) and rely on the capability allowlist, seccomp,
AppArmor, and `readOnlyRootFilesystem: true` documented above to deliver
the actual hardening. Do **not** apply `restricted` or `baseline` PSS to
the namespace — it will fail admission for legitimate reasons that the
agent cannot work around.

If your platform enforces PSS via a custom OPA / Kyverno policy, treat
node-agent like other kernel-adjacent DaemonSets (e.g. CNI plugins,
Cilium agent, Falco): allow `hostNetwork`, `hostPID`, and the
capability set above, and audit-log any other deviation.

## Network exposure and NetworkPolicy

The node agent opens the following ports inside its host network
namespace:

| Port | Protocol | Endpoint | Auth | Notes |
|---|---|---|---|---|
| `$FERRUM_ADMIN_HTTP_PORT` (binary default `9000`; Helm `nodeAgent.admin.port` default `19090`) | TCP / HTTP | `/metrics`, `/health`, `/overload` | Unauthenticated | Disabled unless `FERRUM_NODE_AGENT_ADMIN_ENABLED=true`. When enabled, defaults to `127.0.0.1` unless `FERRUM_ADMIN_BIND_ADDRESS` or `FERRUM_ADMIN_ALLOWED_CIDRS` is set — see [`docs/node_agent.md`](node_agent.md). |
| n/a | n/a | No gRPC, no DP↔CP listener, no proxy listener | — | The node agent is not a proxy and does not accept business traffic. |

Because the agent runs in the host network namespace, "binding to
loopback" means the **host's** loopback — not the container's. A
loopback-bound admin listener is therefore only reachable from processes
on the same node (which is the intended scrape pattern: a node-local
Prometheus sidecar / DaemonSet).

Recommended NetworkPolicy for the node-agent namespace:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ferrum-node-agent-default-deny
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: ferrum-mesh-node-agent
  policyTypes: ["Ingress", "Egress"]
  egress:
    # Kubernetes API server only (resolved via cluster DNS or env)
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    - ports:
        - protocol: TCP
          port: 443    # API server
        - protocol: TCP
          port: 6443   # API server (kubeadm default)
  # No ingress rules — loopback-only admin doesn't traverse the pod network.
```

NetworkPolicy has **no effect on `hostNetwork: true` pods** because the
CNI does not see their traffic. Operators relying on per-pod
NetworkPolicy for compliance must use a node-level firewall (iptables /
nftables / cilium hostFirewall) to enforce egress from the node-agent.

## CNI install lifecycle

Opting in to `nodeAgent.cni.enabled=true` gives three short-lived workloads
write access to two shared host directories, `/opt/cni/bin` and
`/etc/cni/net.d`. Those directories belong to the cluster's primary CNI, so
the security question is not "can Ferrum write there" — it must — but "what
bounds what Ferrum writes and deletes there".

**Availability is part of the threat model here.** While the chain is
installed, `ferrum-cni` is in the ADD path of every pod on the node and fails
closed when the node-agent is unreachable, so an unremovable or stranded
conflist is a node-wide denial of pod creation. That is why removal exists,
why it is automatic on `helm uninstall`, and why a cleanup that cannot
complete reports failure instead of success (see
[docs/node_agent.md](node_agent.md) → "CNI plugin install").

| Workload | Runs | Access | Bound |
|---|---|---|---|
| `ferrum-cni-installer` (init container) | at pod start | rw on both host dirs + socket dir | Durable artifacts: `<hostBinDir>/ferrum-cni`, the configured conflist name, `/etc/cni/net.d/.ferrum-cni-owned.marker` (ownership manifest), and `/etc/cni/net.d/.ferrum-cni-install.lock` (lifecycle lock; created/updated and left behind by design). Same-directory `O_EXCL \| O_NOFOLLOW` staging siblings are used for binary, conflist, and manifest publishes and are removed on success or failure. Under the lock, install refuses to overwrite an existing target conflist unless that file is a bounded regular single-link object whose Ferrum marker names this same owner, and refuses to replace the shared plugin binary with different bytes while any other configuration still references it. Reads neighbouring configs only to copy the primary's plugin list; never modifies one. On a failure after the preflight it removes the same-owner chain it had classified — re-proved by owner, generation, and device/inode — so a failed upgrade cannot leave the node depending on a node-agent that never starts. |
| `ferrum-cni-rollback` (native sidecar) | from this generation's publication until readiness or the deadline | rw on both host dirs, read on the socket | May remove only artifacts carrying this release's owner **and** this pod's generation. Neither its readiness budget nor its STATUS probe starts until this generation's own conflist is observed on disk — the socket is node-scoped, so an answer from an earlier node-agent generation must not be able to disarm this one's rollback — and cleanup holds the node lifecycle lock, so it cannot act against an install that is still running. |
| `ferrum-mesh-cni-cleanup` (pre-delete hook DaemonSet) | during `helm uninstall` | rw on both host dirs | May remove only artifacts carrying this release's owner. No ServiceAccount token, no RBAC, no Kubernetes API access. Runs `hostNetwork: true`, because a pod needing its own CNI sandbox could not start on a node whose chain is broken. Its readiness marker is retracted at process start and republished only by the run that actually completed cleanup; a symlink or any other non-regular file at the marker path is refused, never followed and never deleted. |
| `ferrum-mesh-cni-cleanup-wait` (pre-delete hook Job) | during `helm uninstall` | Kubernetes API only | No host mounts, runs as non-root. Its Role names one object: `get` + `delete` on `daemonsets` and `get` on `daemonsets/status`, both with `resourceNames: [ferrum-mesh-cni-cleanup]` in the release namespace — no list, no watch, no writes of any other kind. It exists because Helm's hook wait ignores DaemonSets, so without it the release could be deleted mid-cleanup; `delete` is what lets it retire that DaemonSet itself instead of relying on a Helm deletion policy that would also fire on failure. |
| `ferrum-mesh-cni-cleanup` / `-wait` identity (ServiceAccounts, Role, RoleBinding) | for the lifetime of the release | none of their own | Ordinary release resources, deliberately not hook resources: on Helm 3.19+ and v4, a later hook's failure also deletes the earlier `hook-succeeded` hooks in that phase, so identity held that way would disappear exactly when a retry needs it. Grants are unchanged by this; the cleanup ServiceAccount still has no Role at all. |

Removal is gated on evidence written at install time, never on a path guess:

- The conflist must carry `managedBy: ferrum-edge` inside its own `ferrum-cni`
  plugin entry, and its `owner`/`generation` must match the run's scope.
- `<hostBinDir>/ferrum-cni` is a **shared** executable, so it is removed only
  when all of the following hold: this run's chain is gone, no remaining
  `.conf`/`.conflist`/`.json` in the directory still names the `ferrum-cni`
  plugin type, the sibling ownership manifest names *these exact* artifacts
  (`confFileName` / `binaryFileName`), and the manifest's recorded SHA-256
  matches the bytes on disk. A directory that could not be fully scanned, or
  manifest evidence bound to different file names, keeps the binary. Retaining
  an unreferenced executable is inert; deleting one another release still
  chains to is not.
- A manifest's `previousBinarySha256` is an **attestation, not an
  observation**. Hashing whatever already occupies the shared plugin path
  proves nothing about who owns it, so the installer records that digest only
  when the manifest already on disk carries this same owner, names these exact
  artifact names, and had itself already recorded that digest. Every other
  case records `null`: a pre-existing operator or third-party binary can never
  be made removable merely because the installer read it. Because an
  unreferenced binary is inert, retaining it never fails chain cleanup.
- The manifest's `binaryOwned` bit applies the same proof to its current
  digest. Publishing the staged inode sets it; reusing an inode sets it only
  when prior same-owner evidence already attested that inode's digest.
  Byte-identical operator-provided contents alone never transfer ownership.
- Install applies the shared-binary rule in the other direction too: while any
  remaining `.conf`/`.conflist`/`.json` still names `ferrum-cni`, the shared
  executable is not replaced with different bytes. Byte-identical
  republication is not a replacement and stays allowed; an installed object
  that cannot be classified, or a directory that cannot be fully scanned,
  fails safe by refusing the replacement with a fixed error and leaving the
  shared binary and manifest byte-identical.
- A failed install does not get to strand a chain. Everything that can fail on
  uncontrolled input — locating the primary config, building the chain,
  serializing it, staging and gating the binary — runs before any shared
  write, and if a later step still fails the installer removes the same-owner
  chain its preflight had classified, re-proving owner, generation, and
  device/inode under the same lock first. A different owner, or a generation
  that overtook the run, is retained and logged; the original failure is
  always surfaced.
- The configured file name is validated as a single path component, so `..`
  or an embedded separator can never redirect a delete out of the directory.
- Artifacts are opened with `O_NOFOLLOW` and classified against the **open
  handle** (regular file, single link, plausible size). Reads are capped in
  bytes independently of the pre-read length, and the binary is hashed through
  the same handle it was classified on, so the digest that authorizes a
  removal is the digest of the object being removed. Removal re-opens the path
  `O_NOFOLLOW` and refuses unless the device/inode still matches. Symlinks,
  hard-linked files, non-regular files, and oversized files are refused rather
  than removed.
- Temporary files are created `O_EXCL | O_NOFOLLOW` at mode `0600` under an
  unpredictable name in the destination directory, so a pre-planted symlink or
  file at a guessable path cannot be followed or truncated by a root process.
- Every mutating run — install and cleanup alike — holds an exclusive `flock`
  on `/etc/cni/net.d/.ferrum-cni-install.lock` for its whole duration, so two
  Ferrum lifecycle steps on one node can never interleave.
- Install fail-closes under that lock before any staging, manifest, binary, or
  target-config write: an existing configured conflist is overwritten only when
  it classifies as a bounded regular single-link file and its Ferrum ownership
  marker names this same owner. Unmarked, malformed, oversized, symlinked,
  non-regular, hard-linked, or differently-owned targets are refused with a
  fixed error and leave those shared artifacts byte-identical.
- Ownership tokens are bounded to 128 bytes of `[A-Za-z0-9._:/@#-]`, so
  nothing operator-supplied reaches the filesystem or a log line unchecked.
  Cleanup diagnostics report fixed reason strings and operator-configured
  paths only; file contents are never echoed.

**What this does not claim.** The final `unlink` is still by pathname. The
lock removes that race between Ferrum's own processes, and the identity
re-check refuses every swap that lands before it, but against a third party
with write access to a root-owned host CNI directory the window is narrowed,
not closed — and such a party can already replace the primary CNI
configuration outright. The bound that matters is the evidence gate above:
anything Ferrum cannot prove it owns is retained and reported, never removed.

Everything else in the directory — the primary CNI's config, another
meta-plugin's config, another Ferrum release's chain — is retained and
reported, not deleted.

The rollback watcher and cleanup hook run with all capabilities dropped,
`allowPrivilegeEscalation: false`, and `readOnlyRootFilesystem: true`. They
run as UID 0 because `/etc/cni/net.d` and `/opt/cni/bin` are root-owned on
every supported distribution; they hold no Linux capability that would let
them do anything beyond file I/O in the two mounted directories.

## Audit and logging

### Kernel auditd

The `bpf()` syscall is the single most security-relevant syscall the
agent makes. To audit every BPF program load and map operation on the
node:

```bash
# /etc/audit/rules.d/ferrum-bpf.rules
-a always,exit -F arch=b64 -S bpf -F key=ferrum-bpf
-a always,exit -F arch=b32 -S bpf -F key=ferrum-bpf
```

Reload with `augenrules --load`. Log entries appear in
`/var/log/audit/audit.log` keyed `ferrum-bpf` and carry the program
type, map fd, and calling pid.

For tc attach (also security-relevant), audit the netlink socket:

```bash
-a always,exit -F arch=b64 -S socket -F a0=16 -F a2=0 -F key=ferrum-tc
```

(`a0=16` is `AF_NETLINK`; `a2=0` is `NETLINK_ROUTE`. tc filter operations
go via `RTM_NEWTFILTER` on this socket family.)

### Agent structured logs

The node agent emits structured `tracing` events at `info!` / `warn!` /
`error!` levels for every security-relevant lifecycle step:

| Event field | Meaning |
|---|---|
| `"Pod enrolled for eBPF capture"` | Enrollment succeeded; `pod_uid`, `namespace`, `pod_ip`, `include_ports_narrowing` carried in the event. |
| `"Pod unenrolled from eBPF capture"` | Cleanup completed; counterpart to enrolled. |
| `"Failed to attach cgroup program"` | BPF attach failure; `pod_uid`, `program`, `error`. |
| `"SOCK_OPS program attached and event ringbuf pinned"` | Global SOCK_OPS attach completed at startup. |
| `"Kernel does not support eBPF capture, falling back to iptables mode"` | Kernel probe failed (< 5.7 or missing cgroup v2 / bpffs); fallback ruleset will apply. |
| `"iptables ... command failed"` / `"iptables command succeeded"` | Every iptables/ip6tables command run on the fallback path (debug level for success, error for failure). |

The `ferrum_node_agent_attach_errors_total` Prometheus counter exposes
attach failures for alerting. Alert on a non-zero rate per node.

## Compromise containment

If an attacker gains code execution inside the node agent container, the
controls above limit blast radius as follows:

| Attack path | Blocker |
|---|---|
| Container escape via setuid | `allowPrivilegeEscalation: false` |
| Container escape via runtime socket | No runtime socket mounted |
| Read host root filesystem | `readOnlyRootFilesystem: true` (own FS) + no host root mount |
| Spawn arbitrary host syscalls | Seccomp `RuntimeDefault` (and optionally tighter custom profile) |
| Attach BPF to other workloads | Only via `CAP_BPF`+`CAP_NET_ADMIN` already granted — the attacker is bounded to what the agent itself can do. Node-level audit on `bpf()` makes this visible. |
| Forge mesh telemetry | Possible (the agent owns the pinned SOCK_OPS maps). Mesh proxy should treat node-agent telemetry as best-effort, not as authz input. |
| Pivot to API server | RBAC scopes to `get`/`list`/`watch` on `pods` and `nodes` only. Cannot create / patch / delete pods, cannot read secrets, cannot exec into pods. |
| Persistence across restart | BPF programs are detached when the container exits (kernel-tracked via aya link IDs). Pinned maps survive (under `/sys/fs/bpf/ferrum/`) but contain only metric data; the agent unpins on graceful shutdown ([`cleanup_all` in `src/ebpf/loader.rs`](../src/ebpf/loader.rs)). iptables fallback rules are removed by the cleanup path on SIGTERM. |
| Lateral movement to other nodes | hostNetwork is scoped to the local node; the watcher is `spec.nodeName`-scoped; ServiceAccount tokens are projected with short TTL. |

Operators worried about compromised-node-agent scenarios should layer
on **runtime sandboxing** (Falco / Tetragon rules for "BPF program load
from non-allowlisted binary"), **node-level firewalling** (the
node-agent has no egress except API server + DNS — block the rest with
nftables on the host), and **API-server audit logs** for every action
under the `system:serviceaccount:<ns>:ferrum-node-agent` identity.

## Threat-by-threat checklist

| Threat | Mitigation | Owner |
|---|---|---|
| BPF program from compromised image | Sign agent images, pin digests, scan for unexpected BPF program types | Operator |
| Capability creep in chart fork | This document + chart fields use `nodeAgent.security.*` toggles, default to least privilege | Gateway |
| Runtime socket mount (escape vector) | Not present in upstream chart; trusted chart runtime lint in the required `Helm Chart` job (`.github/scripts/check_node_agent_chart_runtime.py`, base-extracted on PRs; the local Helm installer must match the trusted base before that scan) recursively rejects any chart template, values/example input, or chart file fragment that adds Docker/containerd/CRI-O sockets or host storage, common `runtime.sock` spellings, or a true/dynamic `privileged` assignment, and repeats these checks on Helm-rendered default, node-agent/ambient-enabled, and example-values manifests | Operator + Gateway |
| Read-write `/sys/fs/cgroup` (host modification) | Chart mounts `readOnly: true`; verify in your own values overlays | Operator |
| Privileged: true (defeats seccomp) | Chart sets `privileged: false` on the node-agent container; the trusted chart-runtime lint requires every chart `privileged` assignment to remain literal false and rejects true or dynamic Helm-controlled values | Operator + Gateway |
| Unauthenticated /metrics on cluster network | Loopback-only default (see [`docs/node_agent.md`](node_agent.md)); explicit opt-in to broaden | Gateway |
| ServiceAccount token theft | Use projected tokens with short `expirationSeconds`; rotate via kubelet | Operator |
| Excessive RBAC | Chart's ClusterRole is `pods get/list/watch`; it adds read-only `nodes list/watch` only when `nodeAgent.ingressRedirectIfaces` enables the bounded topology cache — verify on fork | Operator + Gateway |
| Audit blind spots | `auditd` rules above; agent emits structured tracing events for every attach | Operator |
| Iptables fallback running on a bad kernel | Default `FERRUM_NODE_AGENT_FALLBACK_MODE=fail`; set `iptables` only on custom images that intentionally support it | Operator |
| AppArmor / SELinux misconfigured | Profile in this doc allows only the documented mounts and syscalls; load before enabling | Operator |
| PSS misconfigured (restricted / baseline) | This doc explicitly states `privileged` is required; do not apply restricted/baseline to the namespace | Operator |
| Pinned BPF maps left behind after crash | Cleanup path unpins on SIGTERM; stale pins are removed by `pin_map_at` on next start | Gateway |
| Kernel exploit via BPF verifier | Track CVEs in your kernel; the agent does not bundle a kernel and inherits the host's | Operator |
