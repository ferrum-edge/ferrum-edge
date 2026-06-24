# NodeWaypoint Secured Transport ADR

Status: H2 implementation in progress

## Context

NodeWaypoint is the sidecarless topology where a per-node Ferrum proxy accepts
traffic captured from many node-local pods. The current live gate proves the
IPv4/IPv6 eBPF capture path, source pod attribution, same-node and cross-node
Service authorization, stale source identity cleanup, production SPIRE Workload
API issuance for per-node NodeWaypoint SVIDs, and direct Pod-IP fail-closed
checks on a two-worker kind cluster. Authenticated node-to-node transport and
destination-side NodeWaypoint policy enforcement are wired through the
SPIFFE-mTLS HBONE relay path; broader explicit direct-inbound enforcement
remains H2 work.

This ADR defines the target transport so implementation can proceed without
adding a plaintext shortcut or routing to a non-existent per-pod HBONE listener.

## Decision

The canonical NodeWaypoint path is:

```text
source workload
  -> source pod-netns capture listener
  -> source NodeWaypoint
  -> SPIFFE-mTLS HBONE to destination NodeWaypoint
  -> destination NodeWaypoint authorization
  -> destination pod application port
```

NodeWaypoint must not materialize a secured target as `podIP:15008`. Pods do
not run HBONE listeners, and using that address would either fail open into a
direct app-port dial later or hide an architectural error behind route fallback.

## Mesh Slice Model

The accepted mesh slice must carry explicit destination NodeWaypoint routing
metadata rather than deriving it from mutable Kubernetes addresses at request
time. A routable workload endpoint needs:

- workload UID, namespace, service account, SPIFFE ID, labels, declared app
  ports, endpoint addresses, node name, node UID, cluster, and network;
- destination NodeWaypoint endpoint address and HBONE port for the node hosting
  that workload;
- expected destination NodeWaypoint SPIFFE ID;
- enough locality and network identity for Service, DestinationRule, health,
  and multi-network policy to choose a workload before the secured hop is
  opened.

The wire contract is `Workload.node_waypoint`: `address`, `hbone_port`
(default `15008`), `spiffe_id`, and optional `node_name`, `node_uid`,
`network`, and `cluster`. The data plane must treat this as destination
metadata for the selected workload, not as a replacement workload identity.

The control plane may derive this from Kubernetes Pods, Nodes, and DaemonSet
endpoints, but the data plane consumes the explicit slice fields. The
Kubernetes core translator now derives the endpoint for service-backed
workloads from a trusted ready host-network NodeWaypoint proxy Pod on the same
node. The proxy Pod must live in `FERRUM_K8S_CONTROLLER_NAMESPACE`, carry
`app.kubernetes.io/name=ferrum-mesh-ambient`, use service account
`ferrum-mesh`, and advertise `FERRUM_MESH_TOPOLOGY=node_waypoint`; scoped
workload watches include that namespace for Pod discovery. Helm sets this to
the release namespace by default and refuses `node_waypoint` renders that
disable the ambient admin health listener, so Kubernetes Pod Ready is backed by
a concrete readiness probe. The proxy Pod IP becomes `address`,
`FERRUM_MESH_HBONE_LISTEN_ADDR` supplies `hbone_port` when present before
falling back to the named `hbone` container port/default,
`FERRUM_MESH_WORKLOAD_SPIFFE_ID` or `FERRUM_GATEWAY_SPIFFE_ID` supplies the
expected `spiffe_id`, and the owning Node object supplies `node_uid` when
available. Pods with `FERRUM_MESH_ALLOW_NO_CA=true` or without an explicit
waypoint SVID identity remain recognized as NodeWaypoint proxy pods for
exclusion purposes, but do not publish `node_waypoint` metadata.
Identity-backed source NodeWaypoint runtimes (file SVID material or mesh CA
backend; production mode requires one of those identity sources) skip
metadata-absent service targets so the route fails closed instead of retaining a
plaintext backend. Explicit no-CA/no-identity development runs keep the
temporary plaintext compatibility fallback; the required live gate now uses
SPIRE-backed production mode instead.
Helm now exposes `ambient.spire.enabled` to mount the SPIRE Agent Workload API
socket and render the `spire_agent` CA backend, workload SPIFFE ID, and
production-mode guardrail for NodeWaypoint proxy Pods. The NodeWaypoint chart
profile requires the workload SPIFFE ID to include the chart-managed
`$(FERRUM_K8S_NODE_NAME)` downward-API token, and Kubernetes discovery resolves
that token from `spec.nodeName` before publishing node waypoint assertors, so a
DaemonSet cannot collapse all waypoints onto one shared production identity.
The live harness installs a minimal SPIRE fixture and registers one workload
entry per Ready node with `k8s:node-name:<node>` selectors, then requires each
ambient NodeWaypoint pod to expose a `workload_api` SVID metric for its expected
node-bound SPIFFE ID.

Implementation status: the data plane now consumes `Workload.node_waypoint`
when it is present on a selected captured-Service workload. It materializes a
secured HBONE target whose outer dial host is the destination NodeWaypoint
endpoint, whose pinned peer identity is the NodeWaypoint SPIFFE ID, and whose
inner CONNECT authority remains the selected workload app address and port.
Kubernetes pod discovery now populates `node_waypoint` for service-backed
workloads when their node has a trusted ready NodeWaypoint proxy Pod;
identity-backed source NodeWaypoint runtimes now make missing destination
metadata fail closed by skipping those targets during materialization. For
identity-backed NodeWaypoint, the mesh-managed destination `mesh_authz` and
`workload_metrics` plugins derive their `trusted_hbone_assertors` list from the
exact SPIFFE IDs in the scope-authorized CP-derived `node_waypoint_assertors`
inventory. That inventory is built from known
`Workload.node_waypoint.spiffe_id` values before namespace/service slice
narrowing, so destination slices can still trust legitimate source
NodeWaypoints. If none exist, the generated list is empty so asserted workload
identity is not honored.
The temporary plaintext compatibility fallback and built-in bare service-account
assertor defaults remain only for explicit no-CA/no-identity development runs.

## Destination NodeWaypoint Identity

Production should use a node-bound NodeWaypoint SVID so a peer can be pinned to
the node that owns the selected workload. The preferred shape is one exact
SPIFFE identity per NodeWaypoint instance or another verifier-visible binding
that is unique per node.

If a deployment temporarily uses a DaemonSet-wide service-account SVID, that
SVID alone is not enough to authorize asserted workload identity in production.
The slice must additionally bind the expected peer identity to an explicit node
or endpoint record, and the destination must verify the incoming connection
against that exact control-plane-authorized binding. Matching an unqualified
service account name is a development-only shortcut and must not authorize a
trusted assertor in production mode.

## Source NodeWaypoint Behavior

The source NodeWaypoint:

- resolves the captured source pod identity from the eBPF cookie record and the
  current slice; missing, zero, collided, stale, or malformed identity fails
  closed;
- selects the destination workload using the existing Service, DestinationRule,
  locality, load balancing, and health policy;
- resolves the selected workload's destination NodeWaypoint metadata from the
  accepted slice;
- opens HBONE over SPIFFE mTLS to the destination NodeWaypoint and pins the
  expected NodeWaypoint SPIFFE ID;
- carries the captured source workload identity through the trusted-HBONE
  assertion mechanism;
- preserves original authority, path, method, application port, and original
  destination semantics needed by downstream policy.

An intended secured NodeWaypoint target must never fall back to an ordinary
plaintext cross-node backend dial.

## Destination NodeWaypoint Behavior

The destination NodeWaypoint:

- requires an authenticated HBONE peer with a SPIFFE identity;
- accepts asserted workload identity only from an exact NodeWaypoint assertor
  authorized by the current slice;
- verifies the asserted source workload still exists in the accepted slice and,
  when available, belongs to the asserting cluster, network, and node;
- rejects unknown, deleted, stale, malformed, or node-mismatched assertions;
- enforces destination AuthorizationPolicy and PeerAuthentication as the
  authoritative decision point;
- keeps the open-relay guard: the effective CONNECT authority must resolve to a
  loopback target or a slice-declared workload hosted locally on this node;
- dials only the selected local workload app port.

Source-side policy may reject early for efficiency, but destination-side policy
is mandatory and must be independently sufficient.

## Same-Node Behavior

Same-node calls use the same identity and destination-policy semantics as
cross-node calls. A same-node optimization is allowed only if it still runs the
destination authorization path under an authenticated, slice-authorized
NodeWaypoint assertor identity. A direct plaintext app-port shortcut is not
allowed.

## Direct Pod Traffic

The H2 production profile rejects direct inbound traffic to enrolled destination
pods unless the flow originates from the authorized destination NodeWaypoint
path. A future redirect design is possible, but TC/XDP/CNI classification alone
does not satisfy this ADR; the enforcement action must prevent the packet from
reaching the app outside destination policy.

The current live gate already asserts denied-source direct Pod-IP attempts do
not reach the destination over IPv4 or IPv6. H2 is not complete until same-node,
cross-node, stale-IP reuse, unmanaged-source, forged-assertion, and production
identity-profile cases are covered.

## Failure Behavior

These conditions fail closed for enrolled in-mesh targets:

- missing source pod identity or source policy scope;
- missing destination NodeWaypoint metadata;
- missing or unverifiable gateway SVID material;
- mTLS handshake failure or peer SPIFFE mismatch;
- unknown, stale, malformed, or unauthorized asserted source identity;
- destination workload not hosted locally on the contacted NodeWaypoint;
- partial IPv6 readiness for the affected address family;
- stale route or endpoint generation;
- any attempted secured-route downgrade to plaintext.

The last accepted slice may continue serving during control-plane outage, but
new or changed identities are not trusted until they appear in an accepted
slice.

## Observability

The implementation must add bounded-cardinality metrics for:

- NodeWaypoint HBONE handshake success and failure;
- asserted source identity accepted or rejected, with a bounded rejection
  reason;
- destination policy rejection;
- missing destination NodeWaypoint metadata;
- prohibited plaintext fallback attempts.

SPIFFE IDs, pod names, node names, and remote URLs must not appear in metric
labels.

## Live Assertion IDs

The current live harness records these H2 assertion IDs without promoting
NodeWaypoint beyond Experimental:

- `node_waypoint.ebpf.chart_profile`
- `node_waypoint.ebpf.capture_ready`
- `node_waypoint.ebpf.bpf_attached`
- `node_waypoint.ebpf.registry_ready`
- `node_waypoint.mesh_slice.accepted`
- `node_waypoint.ipv4.service_allow_same_node`
- `node_waypoint.ipv4.service_allow_cross_node`
- `node_waypoint.ipv4.service_deny_same_node`
- `node_waypoint.ipv4.service_deny_cross_node`
- `node_waypoint.ipv4.pod_ip_bypass_guard_same_node`
- `node_waypoint.ipv4.pod_ip_bypass_guard_cross_node`
- `node_waypoint.identity.stale_cleanup`
- `node_waypoint.identity.spire_chart_profile`
- `node_waypoint.ipv6.pod_ip_fail_closed` (historical pre-admission evidence;
  retained as a non-required artifact once IPv6 admission is enabled)
- `node_waypoint.ipv6.service_fail_closed` (historical pre-admission evidence;
  retained as a non-required artifact once IPv6 admission is enabled)
- `node_waypoint.ebpf.registry_ready_ipv6`
- `node_waypoint.ipv6.service_allow`
- `node_waypoint.ipv6.service_deny`
- `node_waypoint.ipv6.pod_ip_bypass_guard`

Future H2 PRs should extend this list instead of renaming these IDs so artifacts
remain comparable across commits.
