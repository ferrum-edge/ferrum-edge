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
checks `/metrics` for `ferrum_node_agent_capture_state{state="ready"} 1`,
collects BPF program/link/map evidence with `bpftool`, creates same-node and
cross-node source/destination pods, verifies `src-a` Service ClusterIP traffic
is admitted, verifies `src-b` Service ClusterIP and direct Pod-IP attempts are
rejected by the live `AuthorizationPolicy`, and checks stale source identities
stay denied after pod recreation. On dual-stack clusters it also requires the
IPv6 pod-netns ready markers, IPv6 Service allow/deny behavior, and an IPv6
direct Pod-IP bypass guard.

Each run writes `target/node-waypoint-ebpf-live/live-assertions.json` using the
shared live-assertion schema from `tests/k8s/lib/live_assertions.sh`. The current
assertions are H2 evidence only; they do not promote NodeWaypoint or make it a
release-blocking GA contract row.

The ambient proxy is started with `FERRUM_MESH_ALLOW_NO_CA=true` because this
disposable test targets eBPF capture, pod attribution, policy enforcement, and
fail-closed bypass coverage, not mesh mTLS identity issuance.
Production installs must provide gateway SVID material or a CA backend instead.

Run manually:

```bash
FERRUM_EBPF_LIVE_ACK_DISPOSABLE=true \
tests/k8s/node_waypoint_ebpf_live/run.sh
```

Set `FERRUM_LIVE_REQUIRE_DUAL_STACK=true` for the dual-stack pass.
Set `FERRUM_LIVE_DOCKER_NODE_EVIDENCE=true` when running against kind from the
Docker host; the harness will collect BPF evidence through the kind node
containers instead of pulling a separate `kubectl debug` image.
