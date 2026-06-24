# NodeWaypoint eBPF live datapath test

This harness validates the sidecarless NodeWaypoint capture path on a real
Linux Kubernetes cluster. It is intentionally not self-skipping: the CI job that
calls it must provide a disposable cluster with:

- at least two schedulable worker nodes;
- kernel >= 5.7, cgroup v2, and bpffs mounted;
- the capabilities and mounts from `docs/node_agent_security.md`;
- Istio security/networking CRDs installed so Ferrum CP can ingest
  `AuthorizationPolicy` and service/workload resources;
- `kubectl`, `helm`, `curl`, and node-level `bpftool` access through
  `kubectl debug node/...`.

The script renders the chart first and fails if an enabled eBPF node-agent or
NodeWaypoint proxy would use a non-`-ebpf` image. It then installs the chart,
installs a minimal SPIRE Server/Agent fixture by default, registers per-node
NodeWaypoint SVID entries, checks that every ambient NodeWaypoint pod reports a
matching `ferrum_mesh_cert_expiry_seconds{source="workload_api"}` metric, checks
`/metrics` for `ferrum_node_agent_capture_state{state="ready"} 1`, collects BPF
program/link/map evidence with `bpftool`, creates same-node and cross-node
source/destination pods, verifies `src-a` Service ClusterIP traffic is admitted,
verifies `src-b` Service ClusterIP and direct Pod-IP attempts are rejected by the
live `AuthorizationPolicy`, and checks stale source identities stay denied after
pod recreation. In production SPIRE mode it also verifies that every ambient
DaemonSet pod rejects plaintext and no-client-SVID connections to the HBONE
listener. The no-client-SVID probe uses a valid authority-form CONNECT target
and accepts only a transport/protocol failure or Ferrum's explicit
`{"error":"Mesh authorization denied: missing per-pod policy scope"}` 403 denial,
not a generic non-200 response. It then temporarily pins the trusted HBONE
assertor inventory to a wrong SPIFFE ID to prove authenticated but untrusted
asserted workload identity fails closed with an attributed policy deny and
recovers after the default inventory is restored. That forged-assertion probe
accepts a direct 403 or the source-side 502 wrapper that explicitly reports the
destination HBONE CONNECT was rejected with 403; in both cases the destination
policy-deny counter for the expected NodeWaypoint assertor must increase.
On dual-stack clusters it also requires the IPv6 pod-netns ready
markers, IPv6 Service allow/deny behavior, and an IPv6 direct Pod-IP bypass
guard.

The chart render preflight and live install both verify the production identity
profile: `ambient.spire.enabled=true` must mount the SPIRE Agent Workload API
socket into the NodeWaypoint proxy and render
`FERRUM_MESH_CA_BACKEND=spire_agent`, `FERRUM_MESH_SPIRE_AGENT_SOCKET`,
per-node `FERRUM_MESH_WORKLOAD_SPIFFE_ID` using `$(FERRUM_K8S_NODE_NAME)`, and
`FERRUM_MESH_PRODUCTION_MODE=true`. The SPIRE fixture follows the upstream
Kubernetes k8s_psat registration pattern: each NodeWaypoint workload entry is
registered under the attested per-node SPIRE Agent parent ID, using the
Kubernetes node UID in
`spiffe://<trust-domain>/spire/agent/k8s_psat/<cluster>/<node-uid>`, plus
`k8s:node-name:<node>` so each NodeWaypoint DaemonSet pod receives the SVID
that discovery later pins for that node.

Each run writes `target/node-waypoint-ebpf-live/live-assertions.json` using the
shared live-assertion schema from `tests/k8s/lib/live_assertions.sh`. The current
assertions are H2 evidence only; they do not promote NodeWaypoint or make it a
release-blocking GA contract row.

Set `FERRUM_LIVE_SPIRE_PRODUCTION=false` only for local eBPF-only debugging. In
that opt-out mode the ambient proxy is started with `FERRUM_MESH_ALLOW_NO_CA=true`;
the required CI workflow keeps production SPIRE enabled so a missing SVID cannot
fall back to plaintext.

Run manually:

```bash
FERRUM_EBPF_LIVE_ACK_DISPOSABLE=true \
tests/k8s/node_waypoint_ebpf_live/run.sh
```

Set `FERRUM_LIVE_REQUIRE_DUAL_STACK=true` for the dual-stack pass.
Set `FERRUM_LIVE_KUBE_CONTEXT=<context>` to run against a disposable cluster
that is not the current kube context; the harness switches to it before cluster
operations.
Set `FERRUM_LIVE_TRUST_DOMAIN=<domain>` to exercise a non-`cluster.local` trust
domain across SPIRE registration, Ferrum Kubernetes identity derivation, and
the workload `AuthorizationPolicy` principals.
Set `FERRUM_LIVE_DOCKER_NODE_EVIDENCE=true` when running against kind from the
Docker host; the harness will collect BPF evidence through the kind node
containers instead of pulling a separate `kubectl debug` image.
