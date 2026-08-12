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
(`mesh.config_transport.native_subscribe`, issue #2002): semantics pinned by
the `mesh_config_transport` conformance module (the namespace-scoped
`MeshSlice` snapshot build MeshSubscribe serves from, `content_eq`
update dedupe that ignores the transport version stamp, and the DP-side
slice apply that fails closed on malformed payloads), live-gated by the
required `sidecar.config.native_subscribe_delivered` assertion — the
`mesh-e2e-sidecar` fixture now deploys a Ferrum CP (`cp` mode, sqlite, K8s
pod discovery building the mesh model from the cluster's real Services and
pods) and a sidecar DP on `FERRUM_MESH_CONFIG_PROTOCOL=native` whose captured
inbound datapath only serves traffic if the CP-delivered slice materialized,
with the DP's `GET /mesh/config-drift` attributing the slice to the native
transport. `coverage.md` lists the currently enrolled rows and required live
assertion IDs, which are the authoritative answer to "what regression fails
CI today."

## Current headline state

- **GA track — Ferrum-native sidecar mesh.** `Sidecar` topology + native
  `MeshSubscribe` + SPIRE/SPIFFE mTLS + `AuthorizationPolicy`/`RequestAuthentication`
  + `ServiceEntry` HTTP egress + `REGISTRY_ONLY` + `VirtualService` routing +
  `DestinationRule` LB/timeout/outlier **plus `exportTo` namespace visibility
  and the client → target-service → root-namespace lookup hierarchy**
  (issues #2465 / #2469). Lookup resolution is per destination HOST at both
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
  CP + native-subscribe leg proving CP-delivered `MeshSubscribe` config end to
  end) on every relevant PR and every main push, the artifact is
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
  `Ambient` HBONE, HTTP-family `EgressGateway`, `ServiceWaypoint` (GAMMA).
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
  into the live harness and remain required Beta gates — see
  `docs/plans/node_waypoint_transport_adr.md`;
  Helm must mount the shared node-agent ↔ ambient pod registry plus host
  cgroup/bpffs views and `SYS_ADMIN`/`SYS_PTRACE` netns capabilities for
  `node_waypoint`), eBPF ambient capture (Dev-only; enabled chart topologies
  auto-select `-ebpf` images -- or the tools-capable `-ebpf-tools` superset for
  the Ambient UDP lifecycle, which shells out -- and non-eBPF builds cannot
  report Ready),
  stream-family egress.

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
  external DNS clusters, SDS, ECDS/RTDS, and delta xDS stay out of scope. See
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
  scope-authorized workloads before namespace/service slice narrowing.
  Explicit no-CA/no-identity development runs retain the temporary plaintext
  fallback and built-in assertor defaults. The pod-veth tc guard now drops
  unmanaged direct Pod-IP attempts to enrolled destination pods unless the
  destination HBONE relay set the authorized socket mark. The live gate also
  forces source workload IPv4 reuse in the disposable kind CNI and proves the
  replacement UID/identity is admitted while stale registry state is gone, then
  restarts the SPIRE Agent and NodeWaypoint DaemonSets and proves SVID-backed
  traffic, policy, and HBONE authentication recover.
- **UDP/DTLS per-pod authz scoping on NodeWaypoint** — architectural (no UDP
  capture hooks); enforcing namespace/selector-scoped policies with UDP/DTLS
  services or proxies force the NodeWaypoint UDP/DTLS path closed during config
  preparation while the policy update still applies to supported TCP/HTTP
  traffic. Mesh-wide UDP/DTLS policy stays supported, and Sidecar remains the
  supported topology for workload-scoped UDP/DTLS authorization.
- **DR `connectionPool.http.maxRequestsPerConnection`** — parsed and validated
  but **Deferred** in status; backend close-after-N-requests is unsupported, so
  it is not projected as effective policy. Use `http2MaxRequests`.
  (`http1MaxPendingRequests` IS enforced through Ferrum's documented honest
  reinterpretation — a 503-on-overflow concurrent in-flight-request gate on the
  HTTP/1.1 dispatch path; see the DR table in `docs/mesh.md`.)
- **DR `subsets[].trafficPolicy.portLevelSettings`** — detected and listed in
  `deferred_fields` with a translate-time warning, but not applied. Ferrum
  honors only top-level `trafficPolicy.portLevelSettings` (Istio's
  highest-precedence subset port-level tier is unsupported). Express per-port
  policy at top-level or via subset `connectionPool` fields; see `docs/mesh.md`.
- **LB `MAGLEV` / `PASSTHROUGH`** — niche; `PASSTHROUGH` approximates to round-robin.
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
| Enrolled Ambient destination pod UDP round trip (source-capture → HBONE → destination pod-netns relay; tc-inbound admit + reply socket inside destination pod netns) | [#3621](https://github.com/ferrum-edge/ferrum-edge/issues/3621) | `docs/mesh.md` UDP TPROXY capture footnote [12] |

Completed historical rows (do **not** re-list as open): EgressGateway UDP `ServiceEntry` materialization (#3263 — external UDP ports materialize a datagram-over-mesh destination allowlist consumed by the gateway's authenticated mesh CONNECT terminator, plus the source-side `Sidecar`/`Ambient` producer that originates the identity-pinned `udp` CONNECT to the configured gateway; still no UDP/DTLS listener, by design); Ambient UDP capture producer + privileged live **source-capture** e2e (#2013 / #2038 — host-loopback destination echo only; enrolled-destination residual split to #3621); Ambient native gRPC over HBONE on the standard H1/H2 frontend (#3728 — the shared nested-HTTP/2 transport now serves every frontend; native gRPC still deliberately bypasses the generic HTTP/1.1 HBONE dispatch); VirtualService `tls[]` SNI passthrough L4 routing (`sniHosts` + port); general opaque-TLS SNI L4 routing outside passthrough (#3264 — an ordinary `tcp` stream listener that terminates nothing routes by normalized `server_name`, with fail-closed admission for indeterminate ClientHellos; see [`docs/tcp_udp_proxy.md`](tcp_udp_proxy.md#opaque-tls-sni-routing)); VirtualService `tcp[]`/`tls[]` weighted multi-destination splitting (#3251); remote-discovery JWT audience binding (#2475); subset-scoped DestinationRule HTTP connection-pool policy (#3228 / #3240–#3242); the poller-driven partition and bounded last-good-retention live gate (#3331); NodeWaypoint observability contract + maturity promotion gates (#3334 — ADR evidence table + Experimental→Beta/Beta→GA gates documented; maturity remains Experimental until promotion criteria close).

## How a feature graduates

1. Semantics pinned by a `tests/conformance/` test → eligible for `Beta`.
2. Promoted to `Maturity::Ga` + added to `tests/conformance/ga_contract.yaml`
   once we will fail CI on its semantic regression and have named the required
   live datapath assertions.
3. Covered by a live-datapath e2e job (`mesh-e2e-*`) → full GA / "Stable".
