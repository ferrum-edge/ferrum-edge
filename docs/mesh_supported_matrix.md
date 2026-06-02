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
| **GA** (≙ `docs/mesh.md` "Stable") | Production-suitable; exercised end-to-end against a live data path. A product promise. | **Prescriptive.** Listed in the conformance `GA_CONTRACT` and tagged `Maturity::Ga`; a regression to anything but `Supported` fails CI (`tests/conformance/`). Full GA additionally requires the live-datapath e2e gate (`mesh-e2e-sidecar`, in build-out). |
| **Beta** | Feature-complete and tested, with a documented sharp edge or an owed verification step. | Observational — may be `Deferred` without failing CI. |
| **Experimental** | Usable with a safety-relevant caveat (plaintext, partial enforcement) or live-datapath-unverified. Opt-in; not recommended without compensating controls. | Observational. |
| **Dev-only** | Gated behind a build feature or dev opt-in; not in the default published image. | Observational. |
| **Out-of-scope** | Explicit non-goal, documented so operators stop asking. | Pinned `OutOfScope` in conformance. |

The **prescriptive** distinction is the point: before this contract the
conformance suite was observational ("all-green by design") and a promised
feature could be silently downgraded. Now a GA feature that regresses breaks its
own test. See `tests/conformance/ga_scope.rs` for the gate.

The GA contract is **seeded and grows incrementally** — a feature is enrolled
only once we are prepared to fail CI on its regression. So the contract does not
yet enroll every row the maturity tables label *Stable*; `coverage.md` lists the
currently enrolled (machine-gated) set, which is the authoritative answer to
"what regression fails CI today."

## Current headline state

- **GA track — Ferrum-native sidecar mesh.** `Sidecar` topology + native
  `MeshSubscribe` + SPIRE/SPIFFE mTLS + `AuthorizationPolicy`/`RequestAuthentication`
  + `ServiceEntry` HTTP egress + `REGISTRY_ONLY` + `VirtualService` routing +
  `DestinationRule` LB/timeout/outlier. This is the path being driven to GA
  first (semantics are pinned; live-datapath e2e verification is in build-out).
  An identity-less mesh (no file-based gateway SVID material — the CA backend
  value is not yet wired to load a runtime SVID) **fails startup closed** (no mTLS ⇒ PERMISSIVE would accept plaintext)
  unless `FERRUM_MESH_ALLOW_NO_CA=true`, and `FERRUM_MESH_PRODUCTION_MODE=true`
  refuses it unconditionally — so the GA path cannot silently degrade to
  unauthenticated plaintext. This is enforced at **both** config-validation time
  (presence check) and **runtime** (`enforce_mesh_inbound_fail_closed`): the
  gateway SVID also backs the inbound listener's server cert, and a resolved
  inbound listener that would still come up plaintext (PeerAuthentication
  DISABLE, no usable server identity, or an unloadable SVID verifier) is refused.
- **Beta.** xDS ADS (Ferrum-CP↔Ferrum-DP), `Ambient` HBONE, `EastWestGateway`
  SNI passthrough, HTTP-family `EgressGateway`, `ServiceWaypoint` (GAMMA),
  trust-bundle federation.
- **Experimental.** `NodeWaypoint` sidecarless capture (IPv4-only GAP-2M bridge,
  live-datapath-unverified), eBPF ambient capture (Dev-only; default image ships
  a no-op mock), cross-cluster endpoint discovery, stream-family egress.

## Acceptable residual / out-of-scope (the long tail)

These are deliberately **not** on the GA path because <~10% of mesh deployments
need them, or because they are blocked upstream / architecturally:

- **Stock Envoy / third-party Istio xDS interop** — Ferrum xDS is Ferrum-to-Ferrum
  (security/policy fields ride Ferrum ECDS carriers). Not a drop-in xDS data plane.
- **`EnvoyFilter` / `WasmPlugin`** — use Ferrum custom plugins (`custom_plugins/`).
- **IPv6 ambient / node-waypoint capture** — blocked on the aya BPF verifier for
  the v6 socket-cookie read; dual-stack **sidecar** serves IPv6 fully.
- **UDP/DTLS per-pod authz scoping** — architectural (no UDP capture hooks);
  mesh-wide + fail-closed is the safe invariant.
- **DR `connectionPool.http.maxRequestsPerConnection` / `http1MaxPendingRequests`**
  — blocked on hyper (no close-after-N / pending-queue knob); use `http2MaxRequests`.
- **LB `MAGLEV` / `PASSTHROUGH`** — niche; `PASSTHROUGH` approximates to round-robin.
- **VirtualService `tcp[]` source/dest-CIDR L4 routing** — uncommon; model with a
  stream `Proxy` or east-west SNI passthrough (TLS-SNI L4 routing is on the roadmap).
- **Active-active multi-cluster endpoint discovery at scale** — minority need;
  targets verified-Beta, not GA.

## How a feature graduates

1. Semantics pinned by a `tests/conformance/` test → eligible for `Beta`.
2. Promoted to `Maturity::Ga` + added to `GA_CONTRACT` once we will fail CI on
   its regression (translation/semantic contract).
3. Covered by a live-datapath e2e job (`mesh-e2e-*`) → full GA / "Stable".
