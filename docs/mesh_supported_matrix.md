# Ferrum Mesh — Supported-Feature Matrix (Product Contract)

This is the **contract**: what you can rely on in production, what is in
progress, and what is an explicit non-goal. It is intentionally short. The
detailed per-capability tables live in [`docs/mesh.md` → Maturity and Support
Status](mesh.md#maturity-and-support-status); the per-protocol × per-transport
answer (which protocol rides which mesh transport, same-cluster / cross-cluster /
SD bridge) is [`docs/mesh.md` → Protocol x Topology Support
Matrix](mesh.md#protocol-x-topology-support-matrix); the live, auto-generated
coverage matrix is emitted by the conformance suite to
`target/conformance/coverage.md` (and `coverage.json`).

## Maturity tiers

| Tier | Meaning | Enforcement |
|---|---|---|
| **GA** (equivalent to `docs/mesh.md` "Stable") | Production-suitable; exercised end-to-end against a live data path. A product promise. | **Prescriptive semantically, and live-blocking when enrolled.** Listed in `tests/conformance/ga_contract.yaml` and tagged `Maturity::Ga`; a semantic regression to anything but `Supported` fails CI (`tests/conformance/ga_scope.rs`). Non-`live_deferred` rows are also blocking through the `mesh-e2e-sidecar` and `multicluster-federation` suites on relevant PRs, merge queue runs, and main pushes; explicitly `live_deferred` rows remain semantic gates and are reported as awaiting authorized live enrollment. Both suites validate their emitted `live-assertions.json` against the contract — required IDs present + passed for the exact suite/profile/commit, no duplicate or stale artifacts — but by different mechanisms, because the trusted Cross build policy freezes each workflow's existing Cross-sensitive surfaces. `mesh-e2e-sidecar` validates in-workflow inside its live job (`tests/conformance/live_contract.rs::live_contract_artifact_gate`). `multicluster-federation` cannot add a cargo step to its frozen live job, so its `gate` job — the job that publishes the required check — downloads the published artifact with a SHA-pinned `actions/download-artifact` and validates it with the standard-library `.github/scripts/validate_live_assertions.py` (exact schema/suite/commit/platform profile, six-hour freshness ceiling, no duplicates, exactly the required id set, every required id `pass`). The fixture additionally fails closed on its own `ferrum_live_assertions_require_all_passed`, and the hosted conformance suite (`live_contract.rs`, `mesh_multicluster_federation.rs`) pins both required sets to the enforced, non-`live_deferred` contract rows in the `Tests` aggregate. |
| **Beta** | Feature-complete and tested, with a documented sharp edge or an owed verification step. | Observational — may be `Deferred` without failing CI. |
| **Experimental** | Usable with a safety-relevant caveat (plaintext, partial enforcement) or live-datapath-unverified. Opt-in; not recommended without compensating controls. | Observational. |
| **Dev-only** | Gated behind a build feature or dev opt-in; not in the default published image. | Observational. |
| **Out-of-scope** | Explicit non-goal, documented so operators stop asking. | Pinned `OutOfScope` in conformance. |

The **prescriptive** distinction is the point: before this contract the
conformance suite was observational ("all-green by design") and a promised
feature could be silently downgraded. Now a GA feature that regresses breaks its
own test. See `tests/conformance/ga_scope.rs` for the gate.

The GA contract **grows incrementally** — a feature is enrolled only once we
are prepared to fail CI on its regression. The source of truth is
`tests/conformance/ga_contract.yaml`. The **Stable sidecar traffic surface is
now enrolled vertically** (semantic assertion → contract row → required live
assertion): PeerAuthentication STRICT, AuthorizationPolicy ALLOW/DENY,
RequestAuthentication JWT, DestinationRule `connectTimeout`/`maxConnections`,
and VirtualService CORS, each backed by a `sidecar.*` live assertion the
`mesh-e2e-sidecar` suite must emit and pass. DestinationRule `exportTo`
visibility and lookup-namespace resolution are also GA-enrolled and live
blocking: the sidecar fixture drives those behaviors on the captured client
egress datapath against a multi-namespace DestinationRule model and requires
both emitted assertion IDs to pass. VS CORS's prior deferral closed with issue #1973 — the mesh slice now carries
`virtual_service_cors_policies` and the client sidecar synthesizes the `cors`
plugin onto its materialized outbound routes. **SPIFFE identity plumbing
(SPIRE Agent CA) is now enrolled too** (`mesh.identity.spire_svid_issuance`):
semantics pinned by the `mesh_spiffe_identity` conformance module (SPIFFE ID
parse + Istio `ns/sa` convention, URI-SAN SVID extraction, the inbound
peer-SVID verification decision, the fail-closed SVID slot, and `spire_agent`
backend selection), live-gated by the required `sidecar.spire.workload_entries`
and `sidecar.peer_auth.strict_mtls_authenticated` assertions. **Native
`MeshSubscribe` config transport is now enrolled as well**
(`mesh.config_transport.native_subscribe`, issue #2002 / #3855): semantics pinned by
the `mesh_config_transport` conformance module (the namespace-scoped
`MeshSlice` snapshot build MeshSubscribe serves from, `content_eq`
update dedupe that ignores the transport version stamp, and the DP-side
slice apply that fails closed on malformed payloads), live-gated by the
required `sidecar.config.native_subscribe_*` assertions — the
`mesh-e2e-sidecar` fixture deploys a Ferrum CP (`cp` mode, sqlite, K8s
pod discovery building the mesh model from the cluster's real Services and
pods) and a sidecar DP on `FERRUM_MESH_CONFIG_PROTOCOL=native` whose captured
inbound datapath only serves traffic if the CP-delivered slice materialized
over production mTLS + JWT (`https://ferrum-cp.<ns>.svc.cluster.local:50051`
with SAN verification, CP client-CA, and DP client cert/key). Dedicated
probes prove omit-client / foreign-client / untrusted-server-CA / wrong-SAN /
invalid-JWT fail closed, and a projected Secret generation swap proves watched
CP/DP gRPC TLS rotation reconnects without a pod restart, with the replacement
leaf serial observed over mTLS from the running CP listener. `GET /mesh/config-drift`
attributes the accepted slice to the native transport. `coverage.md` lists the currently enrolled rows and required live
assertion IDs, which are the authoritative answer to "what regression fails
CI today."

## Current headline state

- **GA track — Ferrum-native sidecar mesh.** `Sidecar` topology + native
  `MeshSubscribe` + SPIRE/SPIFFE mTLS + `AuthorizationPolicy`/`RequestAuthentication`
  + `VirtualService` routing + `DestinationRule` LB/timeout/outlier **plus `exportTo`
  namespace visibility and the client → target-service → root-namespace lookup
  hierarchy** (issues #2465 / #2469). Lookup resolution is per destination HOST at both
  layers, the mesh root namespace rides the slice so the data plane can refuse
  a rule outside all three lookup namespaces (missing/blank root provenance
  fails closed rather than restoring permissive Unscoped bucketing), host-owner
  evidence is authoritative over a conflicting upstream container namespace, and
  VirtualService-derived CORS
  policy narrows through the SAME shared `exportTo` evaluator at the same
  enforcement points a DestinationRule does. These DestinationRule semantics are
  pinned by Rust conformance/integration gates **and** by live
  `sidecar.destination_rule.export_to_namespace_visibility` /
  `sidecar.destination_rule.lookup_tier_client_wins` assertions from the
  `mesh-e2e-sidecar` suite. The existing sidecar traffic surface **and the native
  config transport** remain **live-verified
  and blocking**: the `mesh-e2e-sidecar` kind+SPIRE suite drives the real
  captured datapath (STRICT mTLS positive + plaintext-rejected negative,
  destination-side authz 403, JWT valid/missing/invalid, DR exportTo visibility
  + lookup hierarchy, DR connectTimeout
  two-phase timing, DR maxConnections=1 WebSocket hold/reject/release, and a
  CP + native-subscribe leg proving CP-delivered `MeshSubscribe` config over
  production mTLS + JWT with Service-DNS SAN verification, fail-closed
  omit-client / foreign-client / untrusted-server-CA / wrong-SAN / invalid-JWT
  negatives, and watched projected-Secret rotation) on every relevant PR and every main push, the artifact is
  contract-validated, and both the required CI aggregate and `release.yml`
  gate on it.
  An identity-less mesh — no file-based gateway SVID material **and** no CA
  backend (`FERRUM_MESH_CA_BACKEND=spire_agent|internal` + `FERRUM_MESH_WORKLOAD_SPIFFE_ID`) supplying a runtime SVID — **fails startup closed** (no mTLS ⇒ PERMISSIVE would accept plaintext)
  unless `FERRUM_MESH_ALLOW_NO_CA=true`, and `FERRUM_MESH_PRODUCTION_MODE=true`
  refuses it unconditionally — so the GA path cannot silently degrade to
  unauthenticated plaintext. This is enforced at **both** config-validation time
  (presence check) and **runtime** (`enforce_mesh_inbound_fail_closed`, at startup
  and on PeerAuthentication live reload): the gateway SVID also backs the inbound
  listener's server cert, a resolved inbound listener that would serve plaintext
  (PeerAuthentication DISABLE, or no usable server identity) is refused in
  production, and a configured-but-unloadable SVID verifier (TLS without
  trust-domain verification) is fatal regardless of mode.
- **GA track — cross-cluster east-west federation.** `EastWestGateway` SNI
  passthrough + SPIRE trust-bundle federation are enrolled vertically as well
  (issue #2459): `mesh.multicluster.spire_trust_federation`,
  `mesh.multicluster.eastwest_authenticated_datapath`,
  `mesh.multicluster.untrusted_peer_rejected`,
  `mesh.multicluster.trust_revocation_recovery`, and
  `mesh.multicluster.endpoint_failure_recovery` in
  `tests/conformance/ga_contract.yaml`, with semantics pinned by the
  `mesh_multicluster_federation` conformance module (fail-closed federated-bundle
  requirement, federated trust-domain uniqueness, `local_cluster` /
  `RemoteCluster` canonical-identity rejection, peer-trust withdrawal, and the
  east-west gateway host/port floor) plus the `mesh_topology_matrix`
  `EastWestGateway topology` row. The live half is the `multicluster-federation`
  suite on the `kind-spire-multicluster-federation` profile: two SPIRE-federated
  kind clusters proving bidirectional authenticated east-west traffic,
  untrusted-peer rejection, trust revocation → fail-closed → restore → recover,
  and destination black-hole → recover, gated on all thirteen required
  `multicluster.*` assertions by the fixture, by the workflow `gate` job's
  emitted-artifact validation, and by `release.yml` SHA validation. **Excluded
  from that GA contract but Beta:** poller-driven cross-cluster endpoint
  discovery is independently gated by the two-CP/two-DP Toxiproxy partition suite, including bounded
  last-good retention, expiry, same-generation recovery, and in-flight
  withdrawal retirement.
- **Beta.** xDS ADS (Ferrum-CP↔Ferrum-DP), stock xDS interoperability
  (`FERRUM_MESH_CONFIG_PROTOCOL=stock_xds`; discovery-only, policy stays local),
  `Ambient` HBONE, HTTP-family `EgressGateway` (`ServiceEntry` HTTP egress),
  `REGISTRY_ONLY` outbound registry enforcement, `ServiceWaypoint` (GAMMA).
- **Experimental.** `NodeWaypoint` sidecarless capture (IPv4 and IPv6 capture
  paths gated by a privileged live job; secured node-to-node transport,
  production SPIRE, stale source-IP reuse, and inbound direct-pod enforcement
  are live-gated; the job verifier-loads and attaches the IPv4/IPv6 captured-TCP
  first-byte hooks while the hosted Rust suites cover timestamp rejection,
  lifecycle bounds, ABI decoding, and the Prometheus histogram contract; the
  production identity profile now covers Workload API SVID
  issuance, plaintext/no-client-SVID HBONE rejection, forged assertor rejection,
  SPIRE Agent plus NodeWaypoint restart recovery; the ADR observability
  counter-movement assertion IDs
  (`node_waypoint.observability.hbone_handshake_inbound_tls_failure`,
  `node_waypoint.observability.asserted_identity_rejected`,
  `node_waypoint.observability.hbone_handshake_outbound_success`) are wired
  into the live harness and remain required live observability gates for this
  Experimental topology — see
  `docs/plans/node_waypoint_transport_adr.md`;
  Helm must mount the shared node-agent ↔ ambient pod registry plus host
  cgroup/bpffs views and `SYS_ADMIN`/`SYS_PTRACE` netns capabilities for
  `node_waypoint`), eBPF ambient capture (Dev-only; enabled chart topologies
  auto-select `-ebpf` images -- or the tools-capable `-ebpf-tools` superset for
  the Ambient UDP lifecycle, which shells out -- and non-eBPF builds cannot
  report Ready),
  stream-family egress.

## Wildcard-host egress ServiceEntries

An Istio `ServiceEntry` with a wildcard host (`hosts: ["*.example.com"]`,
`location: MESH_EXTERNAL`) is handled according to its transport family:

| Shape | Outcome |
|---|---|
| `resolution: DNS` or `NONE`, HTTP family | **Supported.** The wildcard route and configured target materialize; request dispatch replaces the target with the matching concrete authority before DNS, SNI, and pool selection. |
| `resolution: STATIC` + non-empty `endpoints[]`, HTTP or stream family | **Supported.** The declared endpoint addresses are the dial targets and the wildcard is only the route selector. |
| `resolution: STATIC` + no usable endpoint, HTTP family | **Refused.** STATIC never falls back to resolving the route host or a request authority; without an operator-declared dial target the entry fails closed. |
| `resolution: DNS` or `NONE` (or `STATIC` with no endpoints), stream family | **Refused.** Raw streams have no HTTP authority from which to derive a concrete dial target. The host is skipped with a `hosts[]`-named `warn!`, and the Istio CRD status carries a `spec.hosts[]` entry in `deferred_fields` (`FerrumAccepted` stays `True`). |
| `protocol: UDP` / `DTLS`, **any** resolution | **Refused.** Datagram egress matches the CONNECT `:authority` exactly, so a wildcard authority could never be named by a client. |

For HTTP-family traffic the literal wildcard is only configured selection
identity: the request path clones the selected target with the matching concrete
authority before it can reach DNS or connection setup. A refused stream-family
entry does **not** claim its listen port, so a following exact-host
`ServiceEntry` on the same port still materializes.

**`resolution: NONE` is currently handled identically to `DNS`.** Istio's
original-destination semantics for raw streams are not implemented; stream
entries must declare exact hosts or use `resolution: STATIC` with `endpoints[]`.

## Acceptable residual / out-of-scope (the long tail)

These are deliberately **not** on the GA path because <~10% of mesh deployments
need them, or because they are blocked upstream / architecturally:

- **Stock Envoy / third-party Istio xDS interop, full data-plane parity** —
  Ferrum's `xds` protocol is Ferrum-to-Ferrum (security/policy fields ride
  Ferrum ECDS carriers), so Ferrum is not a drop-in Envoy replacement in an
  existing xDS fleet. The separate `stock_xds` protocol (issue #3317, **Beta**)
  does consume standard v3 CDS/EDS/LDS/RDS from a third-party control plane, but
  for **discovery only**: enforcement policy always comes from the mandatory
  local `FERRUM_MESH_FILE_CONFIG_PATH` document, and traffic shaping, subsets,
  external DNS clusters, SDS, ECDS/RTDS, and delta xDS stay out of scope. That
  discovery half — including update, deletion, NACK, and capability-refusal
  behaviour — is proven on the live data path against a scripted third-party ADS
  server in `tests/functional/functional_mesh_stock_xds_test.rs` (unpinned-peer
  and subset refusals as reachability transitions; foreign-namespace narrowing
  and RBAC / weighted-route capability refusals as exact ACK + diagnostic +
  accepted-service continuity, with semantic unit/integration coverage that
  those constructs contribute no route). See
  `docs/mesh.md` → "Stock Envoy / third-party Istio xDS interoperability".
- **`EnvoyFilter` / `WasmPlugin`** — use Ferrum custom plugins (`custom_plugins/`).
- **`AuthorizationPolicy` `when: experimental.envoy.filters.*`** — the key is
  accepted and the surrounding policy installs (rejecting it would drop the whole
  policy, which is fail-OPEN for a DENY), but Ferrum has no Envoy filter chain to
  source the dynamic metadata from, so the condition is permanently
  **unsourceable**: a DENY rule ignores the field and still matches, while an
  ALLOW/AUDIT rule can never match. Every other documented Istio condition key is
  evaluated — see [`docs/mesh.md` → Condition
  keys](mesh.md#condition-keys) for the per-protocol matrix.
- **`when: destination.ip` on UDP / DTLS** — no UDP capture path records an
  original destination, so there is no trusted destination evidence for a
  datagram session. The condition is unsourceable there and fails closed the same
  way (DENY still applies, ALLOW/AUDIT cannot match). HTTP-family, raw TCP, TLS
  passthrough, and captured mesh inbound all carry it.
- **IPv6 ambient / node-waypoint capture** — sidecar serves IPv6 fully, and the
  NodeWaypoint eBPF live gate now admits captured IPv6 Service traffic through a
  pod-netns `[::1]` listener with `.ready6` evidence. The mesh slice now has a
  `Workload.node_waypoint` destination endpoint contract. Kubernetes pod
  discovery populates it from trusted ready host-network NodeWaypoint proxy
  Pods in `FERRUM_K8S_CONTROLLER_NAMESPACE`, preferring the proxy pod's
  configured HBONE listen address and requiring an explicit waypoint SPIFFE ID
  (`FERRUM_MESH_WORKLOAD_SPIFFE_ID` or `FERRUM_GATEWAY_SPIFFE_ID`) before
  publishing secured metadata. Captured Service targets consume that metadata
  when present by dialing the destination NodeWaypoint over SPIFFE-mTLS HBONE
  while preserving the selected workload as the inner CONNECT authority.
  Identity-backed source NodeWaypoint runtimes skip metadata-absent service
  targets so they cannot become plaintext backends, and destination-side
  `mesh_authz` trusts HBONE baggage only from exact NodeWaypoint SPIFFE IDs in
  the CP-derived `node_waypoint_assertors` inventory, which is built from
  destination-visible, CP-scope-authorized, and bearer-`ns`-authorized
  workloads before namespace/service slice narrowing.
  Explicit no-CA/no-identity development runs retain the temporary plaintext
  fallback and built-in assertor defaults. The pod-veth tc guard now drops
  unmanaged direct Pod-IP attempts to enrolled destination pods unless the
  destination HBONE relay set the authorized socket mark. The live gate also
  forces source workload IPv4 reuse in the disposable kind CNI and proves the
  replacement UID/identity is admitted while stale registry state is gone, then
  restarts the SPIRE Agent and NodeWaypoint DaemonSets and proves SVID-backed
  traffic, policy, and HBONE authentication recover.
- **UDP/DTLS per-pod authz scoping on NodeWaypoint — supported on Linux**
  (issue #3286). The socket-cookie channel stays TCP-only, so UDP/DTLS resolves
  its source workload from a separate exact channel: the kernel-reported ingress
  interface of each datagram (`IP_PKTINFO`/`IPV6_PKTINFO`) joined against the
  node-agent registry's published pod addresses and attested SPIFFE identity. The
  resolved pod's `PolicyScopeCache` is stamped before `mesh_authz`, so
  namespace/selector-scoped `AuthorizationPolicy` enforces per source workload and
  UDP/DTLS service ports and proxies stay routable. A session is unattributable
  when there is no ingress-interface cmsg, when the interface is one no enrolled
  pod owns (all off-node traffic), when two enrolled pods claim it, when the
  source address is not one the interface's pod owns, when the registry entry
  carries no attested identity or address, or when the pod's workload has left
  the live slice. Such a session carries no per-pod scope, and `mesh_authz`
  then applies **exactly the same rule as the TCP stream path**: it is denied
  whenever any enforcing namespace/selector-scoped `AuthorizationPolicy` is
  loaded, and it falls through to mesh-wide evaluation in a mesh that carries
  only mesh-wide policies (which is fully evaluable without a per-pod scope, and
  is the pre-#3286 behaviour for those meshes). It is therefore not true that
  every unattributable UDP/DTLS session is refused at the session boundary
  regardless of policy — scoped enforcement is what makes the refusal.
  Admitted sessions are re-authorized per datagram, so pod churn, veth reuse,
  and registry removal terminate them; a datagram that merely names an
  established session's (forgeable) source tuple from a different ingress
  interface is refused on its own without ending that session. A scoped
  listener whose socket cannot report ingress interfaces at all does not start:
  the bind is reported as failed rather than serving a listener that could only
  deny. The blanket config-preparation suppression of NodeWaypoint UDP/DTLS
  remains only on builds where the channel cannot exist (non-Linux). Mesh-wide
  UDP/DTLS policy is unchanged.
- **NodeWaypoint UDP/DTLS Service-path reachability — supported on Linux**
  (issue #3286 root review). Materializing a listener does not make it
  reachable: a workload addressing its Service ClusterIP has that datagram
  DNAT-ed by kube-proxy to a backing pod and then DROPPED by the pod-veth guard,
  so the Service path was a black hole and only a direct dial to a trusted node
  address worked. Transparent steering (`raw` `--notrack` + `mangle` mark +
  Ferrum-owned `fwmark`/`local` route, scoped `-i <pod veth> -d <ClusterIP>
  --dport <port>`) now delivers that datagram to the materialized listener
  **without rewriting it**, so the source address, the ingress interface, and
  the original destination all survive and the reply is sourced back from the
  ClusterIP through a transparent socket. What is and is not covered:
  - **Proven live** (`node-waypoint-ebpf-live`,
    `node_waypoint.udp.service_path_allow_attributed_source`): an enrolled pod
    sending to a `protocol: UDP` Service's ClusterIP reaches the production
    listener, the backend logs the datagram, and the echo returns — under
    kube-proxy **iptables** mode, IPv4, on kind.
  - **Proven live for DTLS too**
    (`node_waypoint.dtls.service_path_allow_attributed_source`,
    `node_waypoint.dtls.service_path_deny_scoped_policy`, and
    `node_waypoint.dtls.service_path_deny_unattributed_source`): an enrolled pod
    resolves the `dtls-echo` Service DNS name, completes a real
    `openssl s_client -dtls1_2` handshake against its ClusterIP through the
    production listener, its decrypted datagram reaches the backend (which logs
    it) and the echo returns; a namespace-scoped-denied source and an unenrolled
    source both get no application data with the backend proving it saw nothing.
    A steered DTLS session works because the `DtlsServer` PINS the captured
    local destination per peer and sources every encrypted record from it —
    initial handshake flight, ordinary output drain, retransmits, application
    replies, and the final shutdown flush — over a transparent socket. A
    datagram whose capture does not match the pinned one, or that carries no
    capture at all on a scoped listener, is dropped before any session state is
    allocated or delivered. The direct-node-address probes
    (`node_waypoint.dtls.listener_bound`,
    `node_waypoint.dtls.listener_allow_attributed_source`,
    `node_waypoint.dtls.listener_deny_scoped_policy`) are retained as a
    **distinct boundary**, not as substitute evidence for the Service path.
  - **Not exercised, not claimed**: IPv6 Service steering, kube-proxy `ipvs` and
    `nftables` modes, and headless (ClusterIP-less) services, which have no
    address to steer and remain direct-address only.
  - **Requires** `iptables` and `ip` in the NodeWaypoint image (the
    `-ebpf-tools` image) plus `NET_ADMIN`; a `dtls` listener additionally needs
    `NET_ADMIN` (or `NET_RAW` on newer kernels) for its transparent socket, and
    refuses to start without it. Every PUBLISHED address family must be
    installable in full: a node missing `ip6tables` while an IPv6 destination is
    published fails the WHOLE apply, tears every Ferrum-owned object down, and
    retries on the next reconcile — there is no per-family best-effort arm,
    because a published-but-uninstalled family is a silent black hole that
    would never be retried. A node that cannot install the plan leaves the
    Service path unsteered, which is a lost service, never an unauthorized one.
  - **Stale-rule reaping**: the chains, `ip rule`, and route survive the process
    that installed them, so the FIRST reconcile of every process runs the
    exact-name teardown even when it steers nothing; later unchanged polls run
    no command. A generation change empties the `mangle` mark chain BEFORE the
    `raw` notrack chain is repopulated, so no datagram is ever marked under a
    destination generation whose notrack / local-delivery prerequisites do not
    match it. The resulting window is unsteered (fail-closed at the pod-veth
    guard), never cross-generation admission.
  - **Steered interfaces are the PUBLISHED ones.** The steering interface set is
    taken from the source-attribution index's published generation, after its
    own refusals — a contested ingress interface (refused for both claimants), a
    malformed or UID-mismatched binding, a duplicate, and an over-bound
    generation all contribute nothing to steering.
  - **Serving-generation ownership.** Mesh preparation may carry desired
    destinations as candidate metadata; it must not publish the live datapath.
    `StreamListenerManager` publishes only destinations whose UDP/DTLS listeners
    are actually bound on the accepted serving generation, and retracts them
    before those sockets go away (bind failure, deferred DTLS, withdrawal, task
    failure, shutdown). A rejected or merely inspected candidate cannot change
    steering, and a destination is never marked without a serving socket.


  **The listener configuration surface.** The attribution channel is reachable
  because a NodeWaypoint materializes real UDP/DTLS **service listeners** from
  the mesh service inventory (`materialize_node_waypoint_udp_listeners`, opt-in
  via `FERRUM_MESH_NODE_WAYPOINT_UDP_LISTENERS_ENABLED`). Each in-mesh
  `MeshService` port whose protocol is `udp` (opaque datagram relay) or `dtls`
  (frontend DTLS termination — the same L4 transport, selected by an
  `appProtocol: dtls` / port-name hint on a `protocol: UDP` Service port, or by
  a `dtls` Istio `ServiceEntry`/port protocol) materializes ONE datagram
  listener on that port number, forwarding only to the service's backing pods
  whose `node_waypoint.node_name` exactly matches the current
  `FERRUM_K8S_NODE_NAME`, at their resolved `targetPort`. The backend socket's
  authorization mark is node-local metadata and cannot cross nodes; enabling
  the listener surface without that node name therefore fails serving startup
  closed. Materialization runs DP-side in
  `prepare_normalized_gateway_config_for_mesh`, exactly like the east-west and
  egress-gateway stream listeners, so it needs neither a `stream_match` (which
  `Proxy::validate` rejects on `udp`/`dtls`) nor a CP-side carrier. It is
  default-OFF because a NodeWaypoint runs on the host network and enabling it
  claims node-wide port numbers. Fail-closed refusals, each with a
  field-specific log line and no inert leftovers: a port already claimed by a
  mesh runtime listener or another stream proxy, incompatible same-port
  frontend postures (mixed `udp`/`dtls` or multiple `dtls` claimants), an
  ambiguous duplicate `(ClusterIP, port)` owner, a service port with no
  reachable same-node endpoint, and port `0`. Compatible plain-`udp` Services
  with distinct ClusterIPs share one listener and are demultiplexed by exact
  destination. A
  `dtls` port with no usable frontend DTLS material, or a scoped listener whose
  socket cannot report ingress interfaces, fails the BIND and is reported as a
  `StreamBindFailure` in readiness/status rather than starting a black-hole
  listener. A `dtls` port stays unrepresentable at the EgressGateway
  (terminate-and-re-originate has no DTLS origination path) and is refused
  there with its own diagnostic.

  **What is and is not proven, precisely.** The `node-waypoint-ebpf-live` gate
  sends REAL datagrams through this production listener on a multi-pod kind
  cluster (`tests/k8s/node_waypoint_ebpf_live/run.sh`,
  `run_node_waypoint_udp_datapath_checks`): an admitted enrolled source reaches
  the backend and gets its echo, a source denied by a scoped
  `AuthorizationPolicy` gets nothing, an unenrolled source (and the same pod
  FORGING an enrolled pod's source address over a raw socket) is refused
  because attribution is the kernel-reported ingress interface, and a policy
  change then withdrawal denies and restores that datapath with the ambient
  DaemonSet's restart count unchanged. The relay itself is authorized past the pod-veth tc guard the same way the TCP
  inbound relay is: the scoped listener's frontend socket and its per-session
  backend socket carry `NODE_WAYPOINT_INBOUND_AUTH_MARK`, and `tc_inbound`'s
  UDP arms (IPv4 and IPv6) admit a node-sourced datagram carrying that mark
  before falling through to the existing DNS-response carve-out; unmarked UDP
  to an enrolled pod stays dropped. A scoped listener that cannot set that
  mark does not start.

  The spoof probe needs a raw socket, so the `udp-unmanaged` pod is granted
  `NET_RAW` explicitly and the probe prints its `SPOOF-SENT:` marker only after
  `sendto` returns. `node_waypoint.udp.listener_deny_spoofed_source` passes
  only when the forged datagram was ACTUALLY emitted and the backend log proves
  it never arrived; a sandbox that cannot forge fails the required gate closed
  rather than recording a refusal nothing attempted. The unenrolled-source
  refusal remains an independent attribution proof.

  **DTLS carries the same live gate.** The `dtls-echo` Service declares
  `appProtocol: dtls` on a `protocol: UDP` port, so the NodeWaypoint
  materializes a `frontend_tls: true` listener that TERMINATES DTLS on the
  host-netns socket and forwards plaintext datagrams to the backing pod.
  `run_node_waypoint_dtls_datapath_checks` drives a real
  `openssl s_client -dtls1_2` handshake through it from a prebuilt
  `ferrum-live-dtls-client` image (openssl cannot be `apk add`'d from a
  mesh-enrolled pod: `connect4` rewrites that TCP `connect()` to the capture
  listener; UDP `connect()` is left unrewritten so the DTLS client keeps the
  host-netns destination) and records
  `node_waypoint.dtls.listener_bound` (the handshake completes and the listener
  presents the operator DTLS material — proof it bound, not that it was
  configured), `node_waypoint.dtls.listener_allow_attributed_source` (the
  admitted enrolled source's decrypted datagram reaches the backend, which logs
  it, and the echo comes back), and
  `node_waypoint.dtls.listener_deny_scoped_policy` (a source the
  namespace-scoped `AuthorizationPolicy` denies gets no application data AND the
  backend logs nothing from it). Those three are the DIRECT-NODE-ADDRESS
  boundary; the ordinary user path — the Service DNS name / ClusterIP — is
  proven separately by the three `node_waypoint.dtls.service_path_*` assertions
  and neither substitutes for the other.

  Because a `DtlsServer` owns the socket every encrypted record leaves from,
  three socket options are stamped on it BEFORE the server object exists:
  `DtlsServerLimits::socket_mark` (`NODE_WAYPOINT_INBOUND_AUTH_MARK`),
  `DtlsServerLimits::transparent_reply_source` (`IP_TRANSPARENT` /
  `IPV6_TRANSPARENT`, so a steered session can source records from the Service
  ClusterIP), and `DtlsServerLimits::capture_ingress_ifindex` (the
  `IP_PKTINFO` / `IPV6_PKTINFO` capture). A scoped DTLS listener that cannot
  apply any of them fails construction and is reported as a bind failure. The
  allow assertions above are what prove the mark and the pinned reply source are
  really applied end to end.

  The DTLS material itself comes from the DTLS-specific
  `FERRUM_DTLS_CERT_PATH` / `FERRUM_DTLS_KEY_PATH` (+ optional
  `FERRUM_DTLS_CLIENT_CA_CERT_PATH`), which mesh mode now loads at startup and
  the PeerAuthentication live-reload path rebuilds from. `FERRUM_FRONTEND_TLS_*`
  is deliberately NOT reused: on a mesh proxy that pair is the inbound TCP
  listener's server identity, and sharing it would let configuring a DTLS
  listener replace a SPIRE-issued inbound identity. Ordinary (non-generated)
  DTLS without material stays visibly deferred (`FrontendDtlsDeferred`) rather
  than binding. When generated NodeWaypoint DTLS listeners are required, a
  missing dedicated cert/key or a Strict route without
  `FERRUM_DTLS_CLIENT_CA_CERT_PATH` rejects the complete candidate before apply
  and retains last-good.

  Still **not** proven live: IPv6 DTLS, kube-proxy `ipvs`/`nftables` DTLS
  steering, headless UDP/DTLS Services, multiple terminating-DTLS
  claimants on one port, and a bound ordinary operator DTLS listener in the
  same process (that stronger isolation remains unit/integration). Generated
  DTLS client-certificate (mTLS) frontend verification and PeerAuthentication
  PERMISSIVE → STRICT live-reload are proven by the
  `node-waypoint-ebpf-live` assertions `node_waypoint.dtls.reload_*`.
  Ordinary `FERRUM_DTLS_*` slot isolation is proven live only as unchanged
  captured authenticated `/overload` `frontend_dtls_reload.generation` across
  that publication (`node_waypoint.dtls.operator_isolated_across_reload`).
  Same-port plain-UDP Service demultiplexing is proven by
  `node_waypoint.udp.same_port_demux_*`.
- **DR `connectionPool.http.maxRequestsPerConnection`** — parsed and validated
  but **Deferred** in status; backend close-after-N-requests is unsupported, so
  it is not projected as effective policy. Use `maxConcurrentStreams` for
  per-connection HTTP/2 stream concurrency, or `http2MaxRequests` for the
  destination-wide active-request budget.
  (`http1MaxPendingRequests` IS enforced through Ferrum's documented honest
  reinterpretation — a 503-on-overflow concurrent in-flight-request gate on the
  HTTP/1.1 dispatch path, keyed by logical destination
  `(namespace, stable logical upstream/Service identity, optional K8s Service
  UID when stamped, policy port, selected subset)` rather than selected
  endpoint host; mesh VIP/service-host and direct-pod routes for one Service
  share its FQDN identity, while native upstreams retain their resource ids;
  see the DR table in `docs/mesh.md` and issue #3778.)
- **DR `subsets[].trafficPolicy.portLevelSettings`** — detected and listed in
  `deferred_fields` with a translate-time warning, but not applied. Ferrum
  honors only top-level `trafficPolicy.portLevelSettings` (Istio's
  highest-precedence subset port-level tier is unsupported). Express per-port
  policy at top-level or via subset `connectionPool` fields; see `docs/mesh.md`.
- **DR `outlierDetection.consecutiveGatewayErrors` /
  `consecutiveLocalOriginFailures` / `minHealthPercent`** — parsed past and
  listed in `deferred_fields` with a translate-time warning (issue #4292), but
  not applied: Ferrum's passive health keeps one failure bucket
  (`unhealthy_status_codes` + connection errors) and bounds ejection with
  `maxEjectionPercent` alone. `consecutive5xxErrors` IS applied with Istio's
  consecutive-streak semantics; a translated `outlierDetection` that omits both
  `consecutive5xxErrors` and `consecutiveErrors` inherits Istio's default of 5
  (not Ferrum's native threshold of 3), explicit `0` disables the consecutive-5xx
  detector (HTTP 5xx and locally originated connection failures; split mode is
  deferred), and
  a translated block that omits `maxEjectionPercent` inherits Istio's own 10%
  default rather than Ferrum's uncapped native default.
- **`RequestAuthentication` / `Telemetry` `targetRef` / `targetRefs`** — rejected
  (`FerrumAccepted=False` / `Invalid`) rather than translated (issue #4305).
  Only `AuthorizationPolicy` implements end-to-end attachment for either form;
  admitting one on these kinds would read as "no selector" and WIDEN the
  resource to namespace scope — or to the whole mesh in the Istio root
  namespace. Scope these with a workload selector. Structural diagnostics
  (unknown kind, cross-namespace `Service`, missing target, `selector` +
  `targetRefs` conflict) come from the shared AuthorizationPolicy resolver.
- **`RequestAuthentication` `jwtRules[].outputPayloadToHeader` / `fromCookies`**
  — recognized and listed in `deferred_fields` (field name only, never the
  cookie name or header value), but not enforced (issue #4277).
  `outputClaimToHeaders` IS applied: every declared header is stripped from the
  inbound request before validation and re-asserted only from a validated
  claim.
- **VS `http[].route[].headers` on a weighted multi-destination route** —
  listed in `deferred_fields` (issue #4304). A weighted split materializes one
  upstream with weighted targets, so there is no per-destination rule to bind
  the transform to. Single-destination routes DO apply it before the route-level
  `http[].headers` block, matching Envoy's weighted-cluster then route mutation
  order; a route-level `set` wins when both blocks write the same header.
- **LB `MAGLEV`** — niche; `loadBalancer.simple = MAGLEV` is a hard reject at
  translation.
- **Active-active multi-cluster endpoint discovery at scale** — minority need;
  targets verified-Beta, not GA.

## Product deferral index (owed work — issue-tracked)

Distinct from the out-of-scope list above: out-of-scope items are **documented
non-goals** and deliberately carry no issues. The table below is the canonical
tally of **product/operator support deferrals** called out by the mesh support
matrix and residual-gap inventory; each row has an open tracking issue and an
in-place doc anchor. When one of these deferrals lands, close the issue and
update both the in-place doc mention and this index. Test-harness coverage
gaps, performance pre-warm optimizations, and other engineering follow-ups can
stay documented in place without being promoted into this product deferral
ledger unless they change the support contract.

| Deferral | Issue | Doc anchor |
|---|---|---|

Completed historical rows (do **not** re-list as open): EgressGateway UDP `ServiceEntry` materialization (#3263 — external UDP ports materialize a datagram-over-mesh destination allowlist consumed by the gateway's authenticated mesh CONNECT terminator, plus the source-side `Sidecar`/`Ambient` producer that originates the identity-pinned `udp` CONNECT to the configured gateway; still no UDP/DTLS listener, by design); Ambient UDP capture producer + privileged live source-capture **and enrolled-destination** e2e (#2013 / #2038 / #3621 — `functional_mesh_live_source_capture_udp_manager_hbone_round_trip` covers source-capture through HBONE to an echo bound inside the enrolled destination pod netns, and `node-waypoint-ebpf-live` independently proves the marked backend datagram is admitted through the enrolled-pod `tc_inbound` guard while unmarked traffic is dropped); Ambient native gRPC over HBONE on the standard H1/H2 frontend (#3728 — the shared nested-HTTP/2 transport now serves every frontend; native gRPC still deliberately bypasses the generic HTTP/1.1 HBONE dispatch); VirtualService `tls[]` SNI passthrough L4 routing (`sniHosts` + port); general opaque-TLS SNI L4 routing outside passthrough (#3264 — an ordinary `tcp` stream listener that terminates nothing routes by normalized `server_name`, with fail-closed admission for indeterminate ClientHellos; see [`docs/tcp_udp_proxy.md`](tcp_udp_proxy.md#opaque-tls-sni-routing)); VirtualService `tcp[]`/`tls[]` weighted multi-destination splitting (#3251); remote-discovery JWT audience binding (#2475); subset-scoped DestinationRule HTTP connection-pool policy (#3228 / #3240–#3242); the poller-driven partition and bounded last-good-retention live gate (#3331); NodeWaypoint observability contract + maturity promotion gates (#3334 — ADR evidence table + Experimental→Beta/Beta→GA gates documented; maturity remains Experimental until promotion criteria close).

## How a feature graduates

1. Semantics pinned by a `tests/conformance/` test → eligible for `Beta`.
2. Promoted to `Maturity::Ga` + added to `tests/conformance/ga_contract.yaml`
   once we will fail CI on its semantic regression and have named the required
   live datapath assertions.
3. Covered by a live-datapath e2e job (`mesh-e2e-*`) → full GA / "Stable".
