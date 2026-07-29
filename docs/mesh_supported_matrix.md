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
| **GA** (equivalent to `docs/mesh.md` "Stable") | Production-suitable; exercised end-to-end against a live data path. A product promise. | **Prescriptive, at both layers.** Listed in `tests/conformance/ga_contract.yaml` and tagged `Maturity::Ga`; a semantic regression to anything but `Supported` fails CI (`tests/conformance/ga_scope.rs`). The **live** half is equally blocking: the `mesh-e2e-sidecar` and `multicluster-federation` suites run on every relevant PR and every main push, the results are merge-blocking required checks (the dedicated workflows' `Mesh E2E Sidecar Live` and `Multicluster Federation Live` gate jobs, required via branch protection), and `release.yml` refuses to ship a tag whose SHA lacks green live runs for both suites. Both suites validate their emitted `live-assertions.json` against the contract — required IDs present + passed for the exact suite/profile/commit, no duplicate or stale artifacts — but by different mechanisms, because the trusted Cross build policy freezes each workflow's existing Cross-sensitive surfaces. `mesh-e2e-sidecar` validates in-workflow inside its live job (`tests/conformance/live_contract.rs::live_contract_artifact_gate`). `multicluster-federation` cannot add a cargo step to its frozen live job, so its `gate` job — the job that publishes the required check — downloads the published artifact with a SHA-pinned `actions/download-artifact` and validates it with the standard-library `.github/scripts/validate_live_assertions.py` (exact schema/suite/commit/platform profile, six-hour freshness ceiling, no duplicates, exactly the required id set, every required id `pass`). The fixture additionally fails closed on its own `ferrum_live_assertions_require_all_passed`, and the hosted conformance suite (`live_contract.rs`, `mesh_multicluster_federation.rs`) pins both required sets to the enforced, non-`live_deferred` contract rows in the `Tests` aggregate. |
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
`mesh-e2e-sidecar` suite must emit and pass. No row is `live_deferred`: the
last (VS CORS) closed with issue #1973 — the mesh slice now carries
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
  `DestinationRule` LB/timeout/outlier. Semantics are pinned, and the sidecar
  traffic surface **and the native config transport** are now **live-verified
  and blocking**: the `mesh-e2e-sidecar` kind+SPIRE suite drives the real
  captured datapath (STRICT mTLS positive + plaintext-rejected negative,
  destination-side authz 403, JWT valid/missing/invalid, DR connectTimeout
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
- **Beta.** xDS ADS (Ferrum-CP↔Ferrum-DP), `Ambient` HBONE, `EastWestGateway`
  SNI passthrough, HTTP-family `EgressGateway`, `ServiceWaypoint` (GAMMA),
  trust-bundle federation.
- **Experimental.** `NodeWaypoint` sidecarless capture (IPv4 and IPv6 capture
  paths gated by a privileged live job; secured node-to-node transport,
  production SPIRE, stale source-IP reuse, and inbound direct-pod enforcement
  are live-gated; the production identity profile now covers Workload API SVID
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
  auto-select `-ebpf` images and non-eBPF builds cannot report Ready),
  cross-cluster endpoint discovery, stream-family egress.

## Acceptable residual / out-of-scope (the long tail)

These are deliberately **not** on the GA path because <~10% of mesh deployments
need them, or because they are blocked upstream / architecturally:

- **Stock Envoy / third-party Istio xDS interop** — Ferrum xDS is Ferrum-to-Ferrum
  (security/policy fields ride Ferrum ECDS carriers). Not a drop-in xDS data plane.
- **`EnvoyFilter` / `WasmPlugin`** — use Ferrum custom plugins (`custom_plugins/`).
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
- **Ambient native gRPC over HBONE** — explicit non-goal: the Ambient HBONE HTTP
  path relays an inner HTTP/1.1 byte stream through the CONNECT tunnel, so it has
  no HTTP/2 trailer path for native gRPC. Use Sidecar mesh-mTLS for native gRPC,
  or use gRPC-Web pass-through when Ambient transport is required.
- **DR `connectionPool.http.maxRequestsPerConnection`** — parsed and validated
  but **Deferred** in status; backend close-after-N-requests is unsupported, so
  it is not projected as effective policy. Use `http2MaxRequests`.
  (`http1MaxPendingRequests` IS enforced — a 503-on-overflow pending-request gate
  on the HTTP/1.1 dispatch path; see the DR table in `docs/mesh.md`.)
- **LB `MAGLEV` / `PASSTHROUGH`** — niche; `PASSTHROUGH` approximates to round-robin.
- **VirtualService `tcp[]` / `tls[]` unsupported L4 match predicates** —
  `tls[]` SNI passthrough (`sniHosts` + port → passthrough stream proxy) and
  plain `tcp[]` port routing **are supported** (see `docs/mesh.md` L4 routing
  and `tests/integration/mesh_l7_routing_tests.rs`). Residual fail-closed
  predicates the stream layer cannot express:
  `sourceLabels` / `sourceSubnets` / `destinationSubnets` / `gateways` /
  `sourceNamespace`, plus weighted multi-destination splitting. Model those
  with an explicit stream `Proxy` or upstream-backed split — do not treat
  TLS-SNI itself as roadmap work.
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
| EgressGateway UDP `ServiceEntry` materialization (HTTP/TCP stream egress exists; UDP ports still skipped) | [#3263](https://github.com/ferrum-edge/ferrum-edge/issues/3263) | `docs/mesh.md` Egress Gateway / ServiceEntry materialization |
| Subset-scoped DestinationRule HTTP connection-pool policy (`h2UpgradePolicy`, `maxRetries`, `http1MaxPendingRequests`) | [#3228](https://github.com/ferrum-edge/ferrum-edge/issues/3228) / [#3240](https://github.com/ferrum-edge/ferrum-edge/issues/3240)–[#3242](https://github.com/ferrum-edge/ferrum-edge/issues/3242) | `docs/mesh.md` DestinationRule deferred_fields / subset `connectionPool.http` |
| Multicluster poller-driven partition / last-good-retention live gate | [#3331](https://github.com/ferrum-edge/ferrum-edge/issues/3331) | `docs/mesh_multicluster_federation_runbook.md` Harness |

Completed historical rows (do **not** re-list as open): Ambient UDP capture producer + privileged live source-capture e2e (#2013 / #2038); VirtualService `tls[]` SNI passthrough L4 routing; remote-discovery JWT audience binding (#2475); NodeWaypoint observability contract + maturity promotion gates (#3334 — ADR evidence table + Experimental→Beta/Beta→GA gates documented; maturity remains Experimental until promotion criteria close).

## How a feature graduates

1. Semantics pinned by a `tests/conformance/` test → eligible for `Beta`.
2. Promoted to `Maturity::Ga` + added to `tests/conformance/ga_contract.yaml`
   once we will fail CI on its semantic regression and have named the required
   live datapath assertions.
3. Covered by a live-datapath e2e job (`mesh-e2e-*`) → full GA / "Stable".
