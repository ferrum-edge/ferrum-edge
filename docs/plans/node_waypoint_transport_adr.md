# NodeWaypoint Secured Transport ADR

Status: H2 live-gate baseline + observability contract implemented; NodeWaypoint remains Experimental (see Promotion gates)

## Context

NodeWaypoint is the sidecarless topology where a per-node Ferrum proxy accepts
traffic captured from many node-local pods. The current live gate proves the
IPv4/IPv6 eBPF capture path, source pod attribution, same-node and cross-node
Service authorization, stale source identity cleanup, production SPIRE Workload
API issuance for per-node NodeWaypoint SVIDs, and direct Pod-IP fail-closed
checks on a two-worker kind cluster. It also proves plaintext/no-client-SVID
HBONE listener probes are rejected and that authenticated HBONE baggage from an
untrusted assertor fails closed under destination policy. Authenticated
node-to-node transport and destination-side NodeWaypoint policy enforcement are
wired through the
SPIFFE-mTLS HBONE relay path. The destination-side pod-veth tc guard now drops
unmarked direct traffic to enrolled pod IPs and admits only backend dials made
by the destination NodeWaypoint relay with the authorized socket mark.

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
- uses destination-scoped AuthorizationPolicy for the transparent inbound HBONE
  relay only when that trusted source assertion is honored; missing or
  untrusted relay baggage fails closed instead of evaluating under the relay
  identity;
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
pods unless the flow originates from the authorized destination NodeWaypoint path.
The current implementation enforces that with the pod-veth tc classifier
attached on host-side veth ingress:
`FERRUM_POD_IPS` / `FERRUM_POD_IPS6` mark enrolled destination addresses, and
packets to those addresses are dropped unless `skb->mark` equals the
NodeWaypoint inbound-auth mark set by the destination HBONE relay before it
dials the local backend pod. That classifier is intentionally a guard, not a
redirect; unauthenticated direct pod-IP traffic never reaches the app outside
destination policy.

A second, opt-in tc **ingress** classifier (`ferrum_tc_ingress_redirect`, issue
#3287) sits alongside it, off unless
`FERRUM_NODE_AGENT_INGRESS_REDIRECT_IFACES` names capture interfaces. Rather
than dropping in-scope direct pod traffic, it steers it — with
`bpf_sk_assign()`, never NAT — into the mesh proxy's transparent inbound
**capture** listener on `FERRUM_MESH_INBOUND_LISTEN_ADDR`, which is a distinct
protocol boundary from HBONE (`:15008`): it terminates no TLS and relays
captured application bytes at L4. That does not weaken this section's rule,
because the captured connection is then subject to destination policy before
any byte reaches the app:

- the recovered destination must pass the **same** open-relay guard as the
  inbound HBONE relay (a slice-declared in-mesh workload address and port),
  tightened to exactly one unambiguous workload identity, counted as
  `relay_destination_denied` on rejection. This runs first: one capture listener
  serves every enrolled pod on the node, so the two gates below are properties
  of that workload, not of the listener;
- the effective PeerAuthentication posture of **that destination workload** on
  the captured app port must admit plaintext — resolved from the workload's own
  namespace/labels, never from a listener-wide per-port table, so a `PERMISSIVE`
  pod cannot admit plaintext to a `STRICT` pod sharing the app port. `STRICT`
  still refuses direct plaintext and forces the peer onto authenticated mesh
  transport;
- the L4 `on_stream_connect` chain — including `__mesh_authz` — runs with the
  captured app port as the authorization destination and that workload's
  `PolicyScopeCache` stamped on the stream context, so namespace/selector-scoped
  policies are evaluated against the captured destination rather than denied
  `scope_missing`.

The relay's own backend dial carries the same NodeWaypoint inbound-auth mark, so
the pod-veth guard admits it and the redirect bypasses it as already-relayed. An
in-scope packet for which no capture-listener socket resolves is dropped, not
delivered unredirected. Because this listener is not an HBONE session, it
records no `inbound_tls` / `inbound_connect` handshake phase; only the
destination-policy counter above applies to it.

The live gate asserts both denied in-mesh sources and unmanaged non-mesh sources
cannot reach enrolled destination pods directly over IPv4, plus the unmanaged
IPv6 direct-inbound path when the cluster is dual-stack. It also forces source
workload IPv4 reuse in the disposable kind CNI and proves the replacement
UID/identity is admitted while stale registry state is gone. In production
SPIRE mode it additionally proves NodeWaypoint pods receive Workload API SVIDs,
reject plaintext and no-client-SVID HBONE probes, fail closed on authenticated
but untrusted asserted identity, and recover SVID-backed traffic/policy after a
SPIRE Agent plus NodeWaypoint DaemonSet restart.

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

### ADR signal contract (implemented)

Counters are process-static atomics in
`src/modes/mesh/node_waypoint_observability.rs`. They are monotonic across
config reload and SVID rotation, reset on NodeWaypoint (ambient) process
restart, and are unaffected by node-agent restart. Producers are gated by
`set_enabled(true)` at mesh startup when `FERRUM_MESH_TOPOLOGY=node_waypoint`.
SPIFFE IDs, pod/workload/service/node names, IPs, and URLs never appear as
labels.

| Contract signal | Exact metric / admin field | Label set | Producer path | Unit / integration coverage | Live assertion / dashboard | Status |
|---|---|---|---|---|---|---|
| HBONE handshake success/failure | `ferrum_mesh_node_waypoint_hbone_handshakes_total` + `mesh.node_waypoint_observability.hbone_handshakes.*` on authenticated `/health` | `phase` ∈ {`inbound_tls`,`inbound_connect`,`outbound_dial`}, `result` ∈ {`success`,`failure`} | TLS accept (`src/tls/mod.rs`); CONNECT admission (`src/proxy/hbone_proxy.rs`); outbound dial (`HboneConnectionPool::get_tunnel_via` for pooled HTTP/raw-TCP egress and `get_ws_byte_tunnel` for the 1:1 WebSocket byte tunnel; counted per opened CONNECT tunnel, including tunnels multiplexed onto an already-established pooled H2 connection. Datagram tunnels are out of scope — NodeWaypoint emits no UDP capture listener) | `tests/unit/gateway_core/node_waypoint_observability_tests.rs` | mesh-overview NW panels; live IDs `node_waypoint.observability.hbone_handshake_inbound_tls_failure`, `node_waypoint.observability.hbone_handshake_outbound_success` | **Implemented + live-wired** |
| Asserted source identity accepted/rejected | `ferrum_mesh_node_waypoint_asserted_identity_total` + admin `asserted_identity.*` | `result` ∈ {`accepted`,`rejected`}, `reason` ∈ {`honored`,`untrusted_assertor`,`trust_domain_mismatch`,`unauthenticated_hbone`,`malformed`,`stale_or_unknown`} | `mesh_authz` when `per_pod_policy_scoping` | unit observability tests + existing mesh_authz plugin tests | live ID `node_waypoint.observability.asserted_identity_rejected` | **Implemented + live-wired** |
| Destination policy rejection | `ferrum_mesh_node_waypoint_destination_policy_rejections_total` + admin `destination_policy_rejections.*` | `reason` ∈ {`authz_deny`,`scope_missing`,`destination_scope_missing`,`relay_destination_denied`} | `mesh_authz` / open-relay guard — the HBONE relay (`src/proxy/hbone_proxy.rs`) and the transparent inbound capture listener (`src/proxy/node_waypoint_ingress_capture.rs`), which shares the same guard; mutually exclusive with asserted-identity reject for one decision | unit observability tests | Live deny paths exercise authz; counter panels on mesh-overview | **Implemented** |
| Missing destination NodeWaypoint metadata | `ferrum_mesh_node_waypoint_missing_destination_metadata_total` + admin field | none | `build_outbound_mesh_targets` skip when identity-backed posture requires metadata | `mesh_outbound_node_waypoint_identity_backed_missing_metadata_fails_closed` + observability unit tests | Dashboard panel; live profile always publishes metadata so counter stays observational in H2 | **Implemented** |
| Prohibited plaintext fallback attempt | `ferrum_mesh_node_waypoint_plaintext_fallback_attempts_total` + admin field | none | Same fail-closed skip (blocked plaintext retention) | same as missing-metadata | Dashboard panel | **Implemented** |

### Increment ownership (no double-count of one failed session)

The rule is on the **failure** side: one failed session contributes exactly one
`result="failure"` sample across the three phases. Success samples are per
phase, so a session that clears an earlier phase records that phase's success
even when a later phase then fails.

1. Destination inbound: TLS failure increments **only** `phase=inbound_tls`
   failure. CONNECT admission is never counted for that session.
2. Destination inbound: TLS success then CONNECT reject increments
   `inbound_tls` **success** and, as the session's only failure sample,
   `phase=inbound_connect` failure.
3. Destination inbound: TLS + CONNECT admission success increments
   `inbound_tls` success and `inbound_connect` success (distinct phases of one
   successful session).
4. Source outbound dial is independent (`phase=outbound_dial`).
5. Mesh-wide `ferrum_mesh_mtls_handshake_failures_total` remains the umbrella
   TLS-failure series for all mesh topologies. On NodeWaypoint it correlates
   with `inbound_tls` failures but is a distinct series (not a second ADR
   failure class).

### Overlapping signals (do not duplicate)

| Existing signal | Role | Relationship to ADR set |
|---|---|---|
| `/overload` `node_waypoint_drops.*` | Accept-time cookie/identity drops | Capture/accept path only; not HBONE handshake or authz |
| `ferrum_node_agent_capture_state` | Node-agent capture readiness | Node-agent process; orthogonal |
| `ferrum_mesh_node_topology_degraded` | Node-agent topology degradation | Node-agent process; orthogonal |
| `ferrum_mesh_mtls_handshake_failures_total` | Mesh-wide frontend TLS failures | Umbrella TLS series; NW ADR uses phased NW counters |
| `ferrum_mesh_requests_total{response_code="403"}` | RED deny traffic | Outcome RED; ADR adds reason-bounded policy/identity counters |
| `ferrum_mesh_bpf_*` | SOCK_OPS BPF counters | Transport/kernel events; not authz/handshake contract |
| `GET /mesh/policy-denies/recent` | Authenticated deny ring | Drilldown; counters remain the scrape contract |

### Residual / not claimed in this PR

- Multi-hour soak / upgrade soak artifacts for Beta→GA are **not** produced by
  this PR (see promotion gates).
- Live assertion for missing-metadata / plaintext-fallback counter movement is
  not required by the H2 production profile (metadata is always published);
  unit/materialization coverage pins the producers.

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
- `node_waypoint.ipv4.direct_inbound_guard_same_node`
- `node_waypoint.ipv4.direct_inbound_guard_cross_node`
- `node_waypoint.identity.stale_cleanup`
- `node_waypoint.identity.stale_ip_reuse`
- `node_waypoint.identity.spire_chart_profile`
- `node_waypoint.identity.spire_live_ready`
- `node_waypoint.identity.spire_workload_entries`
- `node_waypoint.identity.workload_api_svid`
- `node_waypoint.identity.plaintext_hbone_rejected`
- `node_waypoint.identity.unauthenticated_hbone_rejected`
- `node_waypoint.identity.forged_assertion_rejected`
- `node_waypoint.identity.spire_restart_recovery`
- `node_waypoint.ipv6.pod_ip_fail_closed` (historical pre-admission evidence;
  retained as a non-required artifact once IPv6 admission is enabled)
- `node_waypoint.ipv6.service_fail_closed` (historical pre-admission evidence;
  retained as a non-required artifact once IPv6 admission is enabled)
- `node_waypoint.ebpf.registry_ready_ipv6`
- `node_waypoint.ipv6.service_allow`
- `node_waypoint.ipv6.service_deny`
- `node_waypoint.ipv6.pod_ip_bypass_guard`
- `node_waypoint.ipv6.direct_inbound_guard`
- `node_waypoint.observability.hbone_handshake_inbound_tls_failure`
- `node_waypoint.observability.asserted_identity_rejected`
- `node_waypoint.observability.hbone_handshake_outbound_success`

Future H2 PRs should extend this list instead of renaming these IDs so artifacts
remain comparable across commits.

### Wired observability IDs

Trusted baseline PR #3427 added these IDs to the SPIRE-production required set.
They are the required Beta gate for representative ADR counter movement:

- `node_waypoint.observability.hbone_handshake_inbound_tls_failure` — scrape
  ambient `/metrics` before and after the plaintext-HBONE rejection check and
  require `ferrum_mesh_node_waypoint_hbone_handshakes_total{phase="inbound_tls",result="failure"}`
  to increase.
- `node_waypoint.observability.asserted_identity_rejected` — after the forged
  assertor check and **before** assertor restore (restart resets the
  process-static counters), require
  `ferrum_mesh_node_waypoint_asserted_identity_total{result="rejected",reason="untrusted_assertor"}`
  to be non-zero.
- `node_waypoint.observability.hbone_handshake_outbound_success` — scrape
  before and after the cross-node Service allow, then require
  `ferrum_mesh_node_waypoint_hbone_handshakes_total{phase="outbound_dial",result="success"}`
  to increase.

The trusted baseline keeps `tests/k8s/node_waypoint_ebpf_live/run.sh` byte-for-byte
aligned with the Cross policy while this PR supplies the producer contract. The
contract is also pinned by
`tests/unit/gateway_core/node_waypoint_observability_tests.rs`, including the
`/metrics` render-cache bypass and the optional `gateway_namespace` label
append that the live selectors would have to tolerate.

## Promotion gates

NodeWaypoint remains **Experimental** after this observability reconciliation.
Promotion is explicit and evidence-backed:

### Experimental → Beta

All of the following must be true:

1. **Semantic conformance.** ADR transport + observability rows above are
   Implemented (this PR). Mesh topology matrix / support matrix still list
   NodeWaypoint as Experimental until Beta criteria close.
2. **Live assertion IDs (required).** Every ID listed under the SPIRE
   production profile in `tests/k8s/node_waypoint_ebpf_live/run.sh`
   `REQUIRED_LIVE_ASSERTIONS` passes on the platform profile
   `kind-dual-stack-node-waypoint-ebpf`, **and** the three wired
   `node_waypoint.observability.*` counter-movement IDs remain in that list and
   pass there too.
3. **Platform profiles.** At least one dual-stack kind profile with IPv4 +
   IPv6 capture admission and SPIRE production identity.
4. **Restart evidence.** `node_waypoint.identity.spire_restart_recovery`
   remains green (SPIRE Agent + NodeWaypoint DaemonSet restart).
5. **Stated non-goals remain non-goals.** Native gRPC over Ambient HBONE and
   per-pod UDP/DTLS policy scoping on NodeWaypoint stay out-of-scope (see
   `docs/mesh_supported_matrix.md`).
6. **Release-blocking failures for Beta candidacy.** Any fail-open plaintext
   fallback under identity-backed posture, any unbounded identity label on NW
   ADR metrics, or loss of the wired observability live assertion IDs, blocks
   Beta.

### Beta → GA

All Experimental→Beta criteria, plus:

1. Enroll a GA contract row in `tests/conformance/ga_contract.yaml` with
   `Maturity::Ga` semantic modules and required live assertion IDs (same
   extend-not-rename rule).
2. Soak / upgrade evidence: multi-hour dual-stack soak with counter monotonicity
   across reload and SVID rotation, plus at least one NodeWaypoint chart upgrade
   without plaintext regression.
3. Supported kernel/CNI/IPv4/IPv6 scope documented in the support matrix with
   live evidence (kernel ≥ 5.7, cgroup v2, bpffs, dual-stack CNI used by the
   live profile).
4. **Release-blocking for GA:** regression of any enrolled GA live assertion,
   fail-open direct pod-IP bypass of destination policy, or loss of fail-closed
   missing-metadata behavior.
