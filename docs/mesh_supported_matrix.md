# Ferrum Mesh — Supported-Feature Matrix (Product Contract)

This is the **contract**: what you can rely on in production, what is in
progress, and what is an explicit non-goal. It is intentionally short. The
detailed per-capability tables live in [`docs/mesh.md` → Maturity and Support
Status](mesh.md#maturity-and-support-status); the live, auto-generated coverage
matrix is emitted by the conformance suite to `target/conformance/coverage.md`
(and `coverage.json`).

## Maturity tiers

| Tier | Meaning | Enforcement |
|---|---|---|
| **GA** (equivalent to `docs/mesh.md` "Stable") | Production-suitable; exercised end-to-end against a live data path. A product promise. | **Prescriptive.** Listed in `tests/conformance/ga_contract.yaml` and tagged `Maturity::Ga`; a regression to anything but `Supported` fails CI (`tests/conformance/`). Full GA additionally requires the live-datapath e2e gate (`mesh-e2e-sidecar`, in build-out). |
| **Beta** | Feature-complete and tested, with a documented sharp edge or an owed verification step. | Observational — may be `Deferred` without failing CI. |
| **Experimental** | Usable with a safety-relevant caveat (plaintext, partial enforcement) or live-datapath-unverified. Opt-in; not recommended without compensating controls. | Observational. |
| **Dev-only** | Gated behind a build feature or dev opt-in; not in the default published image. | Observational. |
| **Out-of-scope** | Explicit non-goal, documented so operators stop asking. | Pinned `OutOfScope` in conformance. |

The **prescriptive** distinction is the point: before this contract the
conformance suite was observational ("all-green by design") and a promised
feature could be silently downgraded. Now a GA feature that regresses breaks its
own test. See `tests/conformance/ga_scope.rs` for the gate.

The GA contract is **seeded and grows incrementally** — a feature is enrolled
only once we are prepared to fail CI on its regression. The source of truth is
`tests/conformance/ga_contract.yaml`. So the contract does not yet enroll every
row the maturity tables label *Stable*; `coverage.md` lists the currently
enrolled semantic rows and required live assertion IDs, which are the
authoritative answer to "what regression fails CI today."

## Current headline state

- **GA track — Ferrum-native sidecar mesh.** `Sidecar` topology + native
  `MeshSubscribe` + SPIRE/SPIFFE mTLS + `AuthorizationPolicy`/`RequestAuthentication`
  + `ServiceEntry` HTTP egress + `REGISTRY_ONLY` + `VirtualService` routing +
  `DestinationRule` LB/timeout/outlier. This is the path being driven to GA
  first (semantics are pinned; live-datapath e2e verification is in build-out).
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
  production SPIRE, and inbound direct-pod enforcement remain H2 residuals;
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
  while preserving the selected workload as the inner CONNECT authority; no-CA
  and no-identity waypoint pods retain the current plaintext compatibility
  fallback. Broader promotion still waits on mandatory fail-closed enforcement,
  production SPIRE, and inbound direct-pod enforcement.
- **UDP/DTLS per-pod authz scoping on NodeWaypoint** — architectural (no UDP
  capture hooks); enforcing namespace/selector-scoped policies with UDP/DTLS
  services or proxies force the NodeWaypoint UDP/DTLS path closed during config
  preparation while the policy update still applies to supported TCP/HTTP
  traffic. Mesh-wide UDP/DTLS policy stays supported, and Sidecar remains the
  supported topology for workload-scoped UDP/DTLS authorization.
- **DR `connectionPool.http.maxRequestsPerConnection`** — parsed and validated
  but **Deferred** in status; backend close-after-N-requests is unsupported, so
  it is not projected as effective policy. Use `http2MaxRequests`.
  (`http1MaxPendingRequests` IS enforced — a 503-on-overflow pending-request gate
  on the HTTP/1.1 dispatch path; see the DR table in `docs/mesh.md`.)
- **LB `MAGLEV` / `PASSTHROUGH`** — niche; `PASSTHROUGH` approximates to round-robin.
- **VirtualService `tcp[]` source/dest-CIDR L4 routing** — uncommon; model with a
  stream `Proxy` or east-west SNI passthrough (TLS-SNI L4 routing is on the roadmap).
- **Active-active multi-cluster endpoint discovery at scale** — minority need;
  targets verified-Beta, not GA.

## How a feature graduates

1. Semantics pinned by a `tests/conformance/` test → eligible for `Beta`.
2. Promoted to `Maturity::Ga` + added to `tests/conformance/ga_contract.yaml`
   once we will fail CI on its semantic regression and have named the required
   live datapath assertions.
3. Covered by a live-datapath e2e job (`mesh-e2e-*`) → full GA / "Stable".
