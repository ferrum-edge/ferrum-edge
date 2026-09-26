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

The script performs these checks:

1. **Render preflight** — renders the chart and fails if an enabled eBPF
   node-agent or NodeWaypoint proxy would use a non-`-ebpf` image.
2. **Install and identity** — installs the chart and (by default) a minimal
   SPIRE Server/Agent fixture, registers per-node NodeWaypoint SVID entries, and
   checks that every ambient NodeWaypoint pod reports a fail-closed SPIRE Agent
   identity proof
   (`ferrum_mesh_cert_expiry_seconds{spiffe_id=<per-node>,source="spire_agent"}`
   with positive expiry, `ferrum_mesh_ca_health{ca_type="spire_agent"} 1`, and
   `ferrum_mesh_trust_bundle_version{trust_domain=<domain>,source="spire_agent"}`
   >= 1).
3. **Capture readiness and ingress topology** — checks `/metrics` for
   `ferrum_node_agent_capture_state{state="ready"} 1`, proves the explicit
   ingress redirect interface set for IPv4 and IPv6, then injects an existing
   but wrong route device both across a replacement startup and as post-start
   route drift. In both cases the node-agent must withdraw readiness with
   bounded topology metrics and recover only after the original routes are
   restored.
4. **BPF evidence** — collects BPF program/link/map evidence with `bpftool`.
5. **Policy datapath** — creates same-node and cross-node source/destination
   pods, verifies `src-a` Service ClusterIP traffic is admitted, and verifies
   `src-b` Service ClusterIP and direct Pod-IP attempts are rejected by the live
   `AuthorizationPolicy`.
6. **Same-IPv4 reuse** — forces the `src-a` workload to be recreated with a new
   UID on the same IPv4 address so stale source identity and registry state
   cannot be reused or block the replacement; the runtime identity snapshot for
   the replacement must not contain the deleted pod's old UID. The assertion
   also waits for the replacement source allow path and a post-recreation deny
   regression check. It is specific to the default
   `kind-dual-stack-node-waypoint-ebpf` profile and its host-local CNI lease
   files; other disposable profiles keep the non-forced delete/recreate
   stale-cleanup check without requiring `stale_ip_reuse`.
7. **Production SPIRE HBONE checks** (production SPIRE mode only):
   - every ambient DaemonSet pod rejects plaintext and no-client-SVID
     connections to the HBONE listener. The no-client-SVID probe uses a valid
     authority-form CONNECT target and accepts only a transport/protocol
     failure or Ferrum's explicit
     `{"error":"Mesh authorization denied: missing per-pod policy scope"}` 403,
     not a generic non-200 response;
   - the trusted HBONE assertor inventory is temporarily pinned to a wrong
     SPIFFE ID to prove authenticated but untrusted asserted workload identity
     fails closed with an attributed policy deny, then recovers after the
     default inventory is restored. The probe accepts a direct 403 or the
     source-side 502 wrapper that explicitly reports the destination HBONE
     CONNECT was rejected with 403; in both cases the destination policy-deny
     counter for the expected NodeWaypoint assertor must increase;
   - the SPIRE Agent and NodeWaypoint ambient DaemonSets are restarted, then the
     harness waits for fresh SPIRE Agent SVID metrics, registry/mesh-slice
     readiness including destination `node_waypoint` metadata (not just
     resource counts), fresh source admission, allow traffic, an HTTP 403 policy
     deny (a Ferrum route-miss 404 is not a deny), and plaintext/no-client-SVID
     HBONE rejection before recording
     `node_waypoint.identity.spire_restart_recovery`.
8. **Observability counters** — asserts ADR counter movement:
   `node_waypoint.observability.hbone_handshake_inbound_tls_failure` (after
   plaintext HBONE rejection),
   `node_waypoint.observability.asserted_identity_rejected` (after forged
   assertor rejection), and
   `node_waypoint.observability.hbone_handshake_outbound_success` (after
   cross-node Service allow).
9. **Dual-stack** — on dual-stack clusters it also requires the IPv6 pod-netns
   ready markers, IPv6 Service allow/deny behavior, and an IPv6 direct Pod-IP
   bypass guard.

The UDP and DTLS listener checks described below run after the traffic checks
and before the IPv6 checks.

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

## NodeWaypoint UDP listener datapath (issue #3286)

`run_node_waypoint_udp_datapath_checks` drives **real datagrams** through the
UDP listener the NodeWaypoint materializes for the in-mesh `udp-echo` Service's
`protocol: UDP` port (`materialize_node_waypoint_udp_listeners`, enabled by
`ambient.env.FERRUM_MESH_NODE_WAYPOINT_UDP_LISTENERS_ENABLED=true` in the Helm
install). The listener binds that port number (`0.0.0.0`) in the node's network
namespace, so a co-located enrolled pod reaches it at
`<trusted node source IP>:$FERRUM_LIVE_UDP_LISTENER_PORT` (default `15353`) and
its source pod is attributed from the kernel-reported ingress interface — its
veth — before `mesh_authz` evaluates scoped policy.

**Probe address contract.** The probes address the listener at a *trusted node
source IP* (`node_waypoint_listener_ip` derives the node's PodCIDR gateway, the
same set `discover_trusted_kubelet_probe_ips` feeds to
`FERRUM_NODE_AGENT_NODE_IPS`), never at the node's `status.hostIP`. Replies
leave with their source pinned by IP(v6)\_PKTINFO to the exact local address the
client targeted, and the node-agent's direct-pod guard admits a datagram to an
enrolled pod only when it carries the relay's socket mark AND its source is a
trusted node source IP. Probing an untrusted node address produces a reply the
node's own guard drops — the documented fail-closed contract, not a datapath
defect — and for DTLS a route-selected source would break the client's connected
socket outright.

The two UDP senders reuse the `src-a` / `src-b` ServiceAccounts, so the same
principal-keyed `AuthorizationPolicy` objects that govern the HTTP checks govern
these datagrams. Assertions, all observed from the datagram outcome:

- `node_waypoint.udp.listener_allow_attributed_source` — the admitted enrolled
  source reaches the backend and receives its echo.
- `node_waypoint.udp.listener_deny_scoped_policy` — the source the
  namespace-scoped `deny-src-b` policy names gets nothing.
- `node_waypoint.udp.listener_deny_unattributed_source` — an unenrolled pod
  (`udp-unmanaged`, outside the mesh namespace) has no registry binding for its
  veth and is refused.
- `node_waypoint.udp.listener_deny_spoofed_source` — the same unenrolled pod
  FORGES the admitted pod's source address over a raw socket and is still
  refused, because attribution is the ingress interface rather than the
  address. The pod is granted `NET_RAW` explicitly and the probe prints its
  `SPOOF-SENT:` marker only after `sendto` returns, so this assertion passes
  ONLY when a forged datagram was actually emitted and the backend log proves
  it never arrived. A sandbox that cannot forge fails the required gate closed
  rather than recording a refusal nothing attempted. The unenrolled-source case
  above remains an independent attribution proof, and the address-forging
  property itself is additionally pinned by
  `one_pod_cannot_obtain_another_pods_scope_by_forging_its_source_address` in
  `tests/integration/mesh_node_waypoint_udp_scope_tests.rs`.
- `node_waypoint.udp.policy_change_denies_live` /
  `node_waypoint.udp.policy_withdrawal_recovers_live` — applying then deleting a
  DENY for the admitted principal converges both ways with the ambient
  DaemonSet's total container restart count unchanged, so recovery is a live
  reload rather than a data-plane restart.

## Same-port UDP Service demultiplexing (issue #3861)

`run_node_waypoint_udp_same_port_demux_checks` drives two compatible plain-UDP
Services (`udp-demux-a` / `udp-demux-b`) that share one numeric port (default
`15355`) with distinct ClusterIPs and distinct echo prefixes. The NodeWaypoint
binds that port once and demultiplexes by the kernel-reported local destination.
Every assertion requires the matching backend log line; a timeout with no
backend hit cannot pass.

- `node_waypoint.udp.same_port_demux_serves_a` /
  `node_waypoint.udp.same_port_demux_serves_b` — each ClusterIP reaches only its
  own backend through the NodeWaypoint path.
- `node_waypoint.udp.same_port_demux_isolated` — A's payload never appears on B
  and B's payload never appears on A.
- `node_waypoint.udp.same_port_demux_shared_client_tuple` — one bound client
  socket addresses both ClusterIPs without session/pending collision.
- `node_waypoint.udp.same_port_demux_retract_a_keeps_b` — deleting Service A
  retracts A (convergence polls time out on a dedicated probe payload; a fresh
  post-convergence proof payload also times out and backend A logs nothing for
  it) while B continues serving, still isolated, with the ambient restart count
  unchanged.

IPv6 same-port UDP is not claimed here: stream listeners bind `0.0.0.0` by
default, and IPv6 Service steering remains a documented residual.

## NodeWaypoint DTLS listener datapath (issue #3286)

`run_node_waypoint_dtls_datapath_checks` drives a **real DTLS handshake and real
application data** through the DTLS half of the same listener family. The
`dtls-echo` Service declares `appProtocol: dtls` on a `protocol: UDP` port, so
`materialize_node_waypoint_udp_listeners` gives its listener `frontend_tls:
true`: the NodeWaypoint TERMINATES DTLS on the host-netns socket and forwards
PLAINTEXT datagrams to the backing pod, which stays an ordinary UDP echo. The
client is `openssl s_client -dtls1_2` from `dtls-src-a` / `dtls-src-b`, which
reuse the `src-a` / `src-b` ServiceAccounts so the same principal-keyed
`AuthorizationPolicy` objects govern these sessions. Those pods are
mesh-enrolled, so the harness cannot `apk add openssl` at runtime: `connect4`
rewrites their TCP `connect()` to the capture listener. openssl is therefore
baked into `ferrum-live-dtls-client:local` (`dtls-client.Dockerfile`) on the
runner and loaded into kind before the workloads start. `connect4`/`connect6`
also leave UDP `connect()` unrewritten so the DTLS client's connected socket
keeps the original host-netns destination.

The listener terminates with material the harness mints per run and publishes as
a TLS Secret mounted through `ambient.extraVolumes` /
`ambient.extraVolumeMounts`, referenced by `FERRUM_DTLS_CERT_PATH` /
`FERRUM_DTLS_KEY_PATH` / `FERRUM_DTLS_CLIENT_CA_CERT_PATH`
(`FERRUM_LIVE_DTLS_LISTENER_PORT`, default `15354`). Initial datapath checks
are still server-only (PERMISSIVE `portLevelMtls` on `dtls-echo`); the reload
checks below present current/stale client certificates. The server certificate
is deliberately not verified by the client.

- `node_waypoint.dtls.listener_bound` — a DTLS 1.2 handshake completes against
  `<trusted node source IP>:$FERRUM_LIVE_DTLS_LISTENER_PORT` (same probe address
  contract as the UDP checks above) and the listener presents the
  operator DTLS material. A completed handshake can only come from a bound
  `DtlsServer`, so this is a datapath observation rather than a manifest one.
- `node_waypoint.dtls.listener_allow_attributed_source` — the admitted enrolled
  source's decrypted datagram reaches the backend (which logs `recv:`) and its
  echo comes back. Because the `DtlsServer` owns the socket every encrypted
  record leaves from, this also proves `DtlsServerLimits::socket_mark` really
  applied `NODE_WAYPOINT_INBOUND_AUTH_MARK`: an unmarked socket's records would
  be dropped by the pod-veth guard.
- `node_waypoint.dtls.listener_deny_scoped_policy` — the source the
  namespace-scoped `deny-src-b` policy names gets no application data back AND
  the backend logs nothing from it.

Those three probe a trusted **node** address. That is a real boundary, but it is
not how a workload reaches a Service, so it is kept as a distinct check and is
never substitute evidence for the path below.

## NodeWaypoint DTLS Service path (issue #3286 root review)

`run_node_waypoint_dtls_service_path_checks` drives the SAME production listener
through the address a workload actually uses: the `dtls-echo` Service DNS name
`dtls-echo.<workload ns>.svc.cluster.local`, resolved inside the client pod, so
the ordinary discovery path is part of what is proven. Without the Service-path
steering this cannot work at all — kube-proxy DNATs the ClusterIP to the backing
pod and the pod-veth guard drops the unmarked datagram — and a steered DTLS
session additionally requires the `DtlsServer` to source EVERY encrypted record
from the pinned ClusterIP, because a `connect()`ed DTLS client discards a record
arriving from any other address.

- `node_waypoint.dtls.service_path_allow_attributed_source` — `dtls-src-a`
  completes a real `openssl s_client -dtls1_2` handshake against the Service DNS
  name, its decrypted datagram reaches the backend (which logs `recv:`), and the
  echo returns under the attributed source.
- `node_waypoint.dtls.service_path_deny_scoped_policy` — `dtls-src-b`, named by
  the namespace-scoped `deny-src-b` policy, reaches the same steered listener and
  gets no application data, with the backend proving it saw nothing.
- `node_waypoint.dtls.service_path_deny_unattributed_source` — `dtls-unmanaged`
  (outside the mesh namespace, no registry binding for its veth, so no steering
  rule names its interface) gets no application data and the backend logs
  nothing: its datagram takes the pre-existing path and dies at the pod-veth
  guard.

## NodeWaypoint DTLS owner-scoped reload isolation (issue #3858)

`run_node_waypoint_dtls_reload_isolation_checks` runs after the PERMISSIVE
generated-listener checks. The harness enables
`FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED` and mounts a current client CA.
It does **not** inject an ordinary operator DTLS listener or depend on a
hidden overlay file beside `FERRUM_DTLS_CERT_PATH`. Hosted-live ordinary-slot
isolation is the authenticated `/overload`
`stream_listeners.frontend_dtls_reload.generation` captured before and after
the generated-owner publication. A bound ordinary listener remaining
byte-identical is unit/integration evidence, not claimed here.

- `node_waypoint.dtls.reload_permissive_to_strict` /
  `node_waypoint.dtls.reload_unauthenticated_rejected` — applying the
  `dtls-echo` PeerAuthentication to STRICT (removing the PERMISSIVE
  `portLevelMtls` overlay) makes new unauthenticated sessions fail closed on
  the generated listener, with handshake failure and backend_hits=0.
- `node_waypoint.dtls.reload_current_ca_admitted` /
  `node_waypoint.dtls.reload_stale_ca_rejected` — the generated listener admits
  the current client CA (real handshake plus backend log) and rejects the
  stale CA, with backend_hits=0 on the reject path.
- `node_waypoint.dtls.operator_isolated_across_reload` — captured ordinary
  `frontend_dtls_reload.generation` and ambient restart count are unchanged
  across that generated-owner publication. This does not prove a bound
  ordinary listener was serving live.

Not exercised live, and therefore not claimed: IPv6 DTLS (and IPv6 Service
steering), kube-proxy `ipvs` and `nftables` modes, headless services,
multiple terminating-DTLS claimants on one port, and a bound ordinary
operator DTLS listener in the same process. Those stay at
unit/integration level or documented residuals.
The live `dtls-echo` Service port starts `PERMISSIVE` via a selector-scoped
`portLevelMtls` overlay so the earlier datapath checks can handshake without a
client cert; the reload sequence then promotes that overlay to STRICT.
AuthorizationPolicy allow/deny is unchanged.

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
containers instead of pulling a separate `kubectl debug` image. The ingress
topology wrong-interface and drift cases require this access. With
`FERRUM_LIVE_TESTS_REQUIRED=1`, missing Docker/node route prerequisites fail the
run rather than skipping those cases.
