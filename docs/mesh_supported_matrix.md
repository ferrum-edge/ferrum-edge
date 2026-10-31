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

The **prescriptive** distinction is the point: the rest of the conformance
suite is observational, but a GA feature that regresses breaks its own test, so
a promised feature cannot be silently downgraded. See
`tests/conformance/ga_scope.rs` for the gate.

The GA contract **grows incrementally**: a feature is enrolled only once we are
prepared to fail CI on its regression. Enrolled rows live in
`tests/conformance/ga_contract.yaml`; the generated
`target/conformance/coverage.md` (emitted by the conformance suite) lists the
enrolled rows and required live assertion IDs; fixture detail is in the
`tests/k8s/*/README.md` of each live suite.

## Current headline state

- **GA track — Ferrum-native sidecar mesh.** `Sidecar` topology + native
  `MeshSubscribe` + SPIRE/SPIFFE mTLS + `AuthorizationPolicy`/`RequestAuthentication`
  + `VirtualService` routing + `DestinationRule` LB/timeout/outlier, `exportTo`
  namespace visibility, and the client → target-service → root-namespace lookup
  hierarchy (issues #2465 / #2469), live-verified and blocking through the
  `mesh-e2e-sidecar` suite on every relevant PR, main push, and `release.yml`
  (required assertion IDs: `target/conformance/coverage.md`).
  An identity-less mesh (no gateway SVID material and no CA backend) **fails
  startup closed** unless `FERRUM_MESH_ALLOW_NO_CA=true`, and
  `FERRUM_MESH_PRODUCTION_MODE=true` refuses it unconditionally; at runtime a
  listener that would serve plaintext in production, or a configured-but-unloadable
  SVID verifier, is refused (see [mesh.md → Internal Dev CA and Production
  Guardrails](mesh.md#internal-dev-ca-and-production-guardrails)).
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
  production identity profile covers Workload API SVID
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

## Support boundaries, deferrals, and non-goals (the long tail)

These items are off the GA path. Each is a **non-goal**, a **deferred** field
(parsed, surfaced in `deferred_fields`, not applied), a **rejected** shape, or a
feature **supported within a stated boundary**. The linked `docs/mesh.md`
section is canonical for the detail.

**Non-goals**

- **Stock Envoy / third-party Istio xDS interop, full data-plane parity** —
  Ferrum's `xds` protocol is Ferrum-to-Ferrum (security/policy fields ride
  Ferrum ECDS carriers), so Ferrum is not a drop-in Envoy replacement in an
  existing xDS fleet. The separate `stock_xds` protocol (issue #3317, **Beta**)
  consumes standard v3 CDS/EDS/LDS/RDS from a third-party control plane for
  **discovery only**: enforcement policy always comes from the mandatory local
  `FERRUM_MESH_FILE_CONFIG_PATH` document, and traffic shaping, subsets,
  external DNS clusters, SDS, ECDS/RTDS, and delta xDS stay out of scope. See
  [Stock Envoy / third-party Istio xDS interoperability](mesh.md#stock-envoy--third-party-istio-xds-interoperability).
- **`EnvoyFilter` / `WasmPlugin`** — use Ferrum custom plugins (`custom_plugins/`).
- **`AuthorizationPolicy` `when: experimental.envoy.filters.*`** — permanently
  **unsourceable** (Ferrum has no Envoy filter chain). The key is accepted so the
  policy still installs (rejecting it would drop a DENY, which fails open): a
  DENY rule ignores the field and still matches, while an ALLOW/AUDIT rule can
  never match. Every other documented Istio condition key is evaluated; see
  [Condition keys](mesh.md#condition-keys).
- **`when: destination.ip` on UDP / DTLS** — unsourceable on the UDP/DTLS
  authorization path even though Linux UDP capture records an original
  destination, and it fails closed the same way (DENY applies, ALLOW/AUDIT
  cannot match). HTTP-family, raw TCP, TLS passthrough, and captured mesh
  inbound carry it. See [Condition keys](mesh.md#condition-keys).
- **LB `MAGLEV`** — `loadBalancer.simple = MAGLEV` is a hard reject at
  translation.
- **Active-active multi-cluster endpoint discovery at scale** — minority need;
  targets verified-Beta, not GA. See [Multi-Cluster](mesh.md#multi-cluster).

**Deferred or rejected fields**

- **DR `connectionPool.http.maxRequestsPerConnection`** — **Deferred**: backend
  close-after-N-requests is unsupported. Use `maxConcurrentStreams` for
  per-connection HTTP/2 stream concurrency or `http2MaxRequests` for the
  destination-wide active-request budget. (`http1MaxPendingRequests` IS
  enforced as a reinterpreted 503-on-overflow in-flight HTTP/1.1 request gate
  keyed by logical destination; issue #3778.) See
  [DestinationRule limitations](mesh.md#destinationrule-limitations--approximations--deferred-fields).
- **DR `subsets[].trafficPolicy.portLevelSettings`** — **Deferred** with a
  translate-time warning; only top-level `trafficPolicy.portLevelSettings` is
  honored. Express per-port policy at top level or via subset `connectionPool`
  fields.
- **DR `outlierDetection.consecutiveGatewayErrors` /
  `consecutiveLocalOriginFailures` / `minHealthPercent`** — **Deferred** with a
  translate-time warning (issue #4292): passive health keeps one failure bucket
  and bounds ejection with `maxEjectionPercent` alone. `consecutive5xxErrors`
  IS applied with Istio's consecutive-streak semantics. Omitting both
  `consecutive5xxErrors` and `consecutiveErrors` inherits Istio's default of 5,
  and omitting `maxEjectionPercent` inherits Istio's 10%, only when no
  lower-precedence outlier tier supplied that value; explicit `0` disables the
  consecutive-5xx detector. See the
  [DestinationRule support matrix](mesh.md#meshdestinationrule).
- **`RequestAuthentication` / `Telemetry` `targetRef` / `targetRefs`** —
  **Rejected** (`FerrumAccepted=False` / `Invalid`, issue #4305): admitting
  either would read as "no selector" and widen the resource to namespace scope,
  or to the whole mesh in the Istio root namespace. Scope these with a workload
  selector. See [RequestAuthentication](mesh.md#requestauthentication) and
  [Telemetry API](mesh.md#telemetry-api).
- **`RequestAuthentication` `jwtRules[].outputPayloadToHeader` / `fromCookies`**
  — **Deferred** (issue #4277), reported by field name only.
  `outputClaimToHeaders` IS applied: every declared header is stripped from the
  inbound request and re-asserted only from a validated claim. See
  [RequestAuthentication](mesh.md#requestauthentication).
- **VS `http[].route[].headers` on a weighted multi-destination route** —
  **Deferred** (issue #4304): a weighted split has no per-destination rule to
  bind the transform to. Single-destination routes apply it before the
  route-level `http[].headers` block, and a route-level `set` wins. See
  [Header Transforms](mesh.md#header-transforms).

**Supported within a stated boundary (Linux NodeWaypoint, Experimental)**

- **IPv6 ambient / NodeWaypoint capture** — sidecar serves IPv6 fully, and the
  NodeWaypoint eBPF live gate admits captured IPv6 Service traffic. Captured
  Service targets dial the destination NodeWaypoint over SPIFFE-mTLS HBONE from
  `Workload.node_waypoint` metadata, which is published only with an explicit
  waypoint SPIFFE ID. Identity-backed source runtimes skip metadata-absent
  targets instead of dialing them in plaintext, and destination `mesh_authz`
  trusts HBONE baggage only from the `node_waypoint_assertors` inventory (see
  [Trusted HBONE Assertors](mesh.md#trusted-hbone-assertors)); only
  explicit no-CA/no-identity development runs keep the plaintext fallback. The
  pod-veth tc guard drops unmanaged direct Pod-IP attempts to enrolled pods.
  See [Destination metadata](mesh.md#destination-metadata-workloadnode_waypoint).
- **UDP/DTLS per-pod authz scoping** (issue #3286) — the source pod is resolved
  from each datagram's kernel-reported ingress interface
  (`IP_PKTINFO`/`IPV6_PKTINFO`) joined against the node-agent registry. An
  unattributable session follows the TCP stream rule: denied whenever an
  enforcing namespace/selector-scoped `AuthorizationPolicy` is loaded, otherwise
  evaluated mesh-wide. Admitted sessions are re-authorized per datagram, and a
  scoped listener whose socket cannot report ingress interfaces does not start.
  Non-Linux builds keep the blanket suppression of NodeWaypoint UDP/DTLS. See
  [Stream and UDP/DTLS scoping summary](mesh.md#stream-and-udpdtls-scoping-summary).
- **UDP/DTLS service listeners and Service-path reachability** — **opt-in** via
  `FERRUM_MESH_NODE_WAYPOINT_UDP_LISTENERS_ENABLED` (default off, because a
  host-network NodeWaypoint claims node-wide ports) and requires
  `FERRUM_K8S_NODE_NAME`. Transparent steering delivers Service ClusterIP
  datagrams to the listener without rewriting them. It requires the
  `-ebpf-tools` image (`iptables`, `ip`) plus `NET_ADMIN`; a `dtls` listener
  also needs `NET_ADMIN` (or `NET_RAW` on newer kernels) for its transparent
  socket and the dedicated `FERRUM_DTLS_CERT_PATH` / `FERRUM_DTLS_KEY_PATH`
  material (never `FERRUM_FRONTEND_TLS_*`). Port conflicts, incompatible
  same-port postures, missing DTLS material, a `Strict` route without
  `FERRUM_DTLS_CLIENT_CA_CERT_PATH`, and a published address family that
  cannot be installed in full all fail closed: a node that cannot steer loses
  the Service path, never authorizes it. A `dtls` port stays unrepresentable at
  the EgressGateway. `node-waypoint-ebpf-live` proves the UDP and DTLS Service
  paths, same-port UDP demultiplexing, and DTLS PeerAuthentication reload under
  kube-proxy iptables mode, IPv4, on kind; the direct-node-address lane is a
  separate boundary, not substitute evidence. **Not exercised and not
  claimed:** IPv6 Service steering and IPv6 DTLS, kube-proxy `ipvs` and
  `nftables` modes, headless (ClusterIP-less) Services (direct-address only),
  multiple terminating-DTLS claimants on one port, and a bound ordinary
  operator DTLS listener in the same process (unit/integration evidence only).
  See [Node Waypoint](mesh.md#node-waypoint).

## Product deferral index (owed work — issue-tracked)

Distinct from the long-tail list above: those items are **documented
boundaries and non-goals**, not owed product work, and deliberately carry no
row here. The table below is the canonical
tally of **product/operator support deferrals** called out by the mesh support
matrix and residual-gap inventory; each row has an open tracking issue and an
in-place doc anchor. When one of these deferrals lands, close the issue and
update both the in-place doc mention and this index. Test-harness coverage
gaps, performance pre-warm optimizations, and other engineering follow-ups can
stay documented in place without being promoted into this product deferral
ledger unless they change the support contract.

| Deferral | Issue | Doc anchor |
|---|---|---|
| _None open._ | — | — |

Completed historical rows (do **not** re-list as open): EgressGateway UDP `ServiceEntry` materialization (#3263 — external UDP ports materialize a datagram-over-mesh destination allowlist consumed by the gateway's authenticated mesh CONNECT terminator, plus the source-side `Sidecar`/`Ambient` producer that originates the identity-pinned `udp` CONNECT to the configured gateway; still no UDP/DTLS listener, by design); Ambient UDP capture producer + privileged live source-capture **and enrolled-destination** e2e (#2013 / #2038 / #3621 — `functional_mesh_live_source_capture_udp_manager_hbone_round_trip` covers source-capture through HBONE to an echo bound inside the enrolled destination pod netns, and `node-waypoint-ebpf-live` independently proves the marked backend datagram is admitted through the enrolled-pod `tc_inbound` guard while unmarked traffic is dropped); Ambient native gRPC over HBONE on the standard H1/H2 frontend (#3728 — the shared nested-HTTP/2 transport now serves every frontend; native gRPC still deliberately bypasses the generic HTTP/1.1 HBONE dispatch); VirtualService `tls[]` SNI passthrough L4 routing (`sniHosts` + port); general opaque-TLS SNI L4 routing outside passthrough (#3264 — an ordinary `tcp` stream listener that terminates nothing routes by normalized `server_name`, with fail-closed admission for indeterminate ClientHellos; see [`docs/tcp_udp_proxy.md`](tcp_udp_proxy.md#opaque-tls-sni-routing)); VirtualService `tcp[]`/`tls[]` weighted multi-destination splitting (#3251); remote-discovery JWT audience binding (#2475); subset-scoped DestinationRule HTTP connection-pool policy (#3228 / #3240–#3242); the poller-driven partition and bounded last-good-retention live gate (#3331); NodeWaypoint observability contract + maturity promotion gates (#3334 — ADR evidence table + Experimental→Beta/Beta→GA gates documented; maturity remains Experimental until promotion criteria close).

## How a feature graduates

1. Semantics pinned by a `tests/conformance/` test → eligible for `Beta`.
2. Promoted to `Maturity::Ga` + added to `tests/conformance/ga_contract.yaml`
   once we will fail CI on its semantic regression and have named the required
   live datapath assertions.
3. Covered by a live-datapath e2e job (`mesh-e2e-*`) → full GA / "Stable".
