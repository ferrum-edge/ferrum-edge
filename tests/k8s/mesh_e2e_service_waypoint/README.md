# ServiceWaypoint mesh live e2e suite (`mesh-e2e-service-waypoint`)

Live validation of ServiceWaypoint L7 VirtualService routing (issue #7503;
design spec [`docs/plans/mesh_virtualservice_servicewaypoint.md`](../../../docs/plans/mesh_virtualservice_servicewaypoint.md)
section 6.4 and Follow-Up 5) on a real kind cluster with SPIRE-issued SVIDs.
One kind cluster runs:

- **ferrum-cp** — a Ferrum control plane (`FERRUM_MODE=cp`, sqlite) whose
  Kubernetes controller watches Pods/Services/EndpointSlices, Istio
  VirtualService and AuthorizationPolicy, and Gateway API Gateway and
  ReferenceGrant across a two-namespace scope (`ferrum`, `beta`;
  `FERRUM_CP_NAMESPACES`). It serves native `MeshSubscribe` over production
  mTLS + JWT (per-run PKI; the CP server SAN is its Service DNS name; DP client
  certificates and JWT are both required). The pinned CRDs come from
  `tests/fixtures/k8s/` and are Established before the CP starts.
- **swp** — a waypoint `Gateway` (`gatewayClassName: istio-waypoint`,
  `istio.io/waypoint-for: service`) and the ServiceWaypoint Deployment
  (`FERRUM_MESH_TOPOLOGY=service_waypoint`, `FERRUM_MESH_WAYPOINT_NAME=swp`,
  native MeshSubscribe, SPIRE identity `sa/swp`, HBONE on `:15008`).
- **Bound Services** (`istio.io/use-waypoint: swp`): `swsvc` (frontend, no
  backing pod; carries the split VirtualService), `swsvc-v1` / `swsvc-v2`
  (native Sidecar backends answering `sw-backend-v1` / `sw-backend-v2`), and
  `swx` (frontend, no backing pod; carries the cross-namespace VirtualService).
- **xsvc** in namespace `beta` — the cross-namespace destination (native
  Sidecar backend answering `sw-xsvc-beta`), admitted only while a
  ReferenceGrant in `beta` allows it.
- **hbone-client** — an init container fetches the pod's SPIRE X.509 SVID
  through the Workload API (`spire-agent api fetch x509 -write`); the curl
  container then opens authenticated HTTP/2 CONNECT tunnels to `swp:15008`
  (`--proxy https://<swp>:15008 --proxy-http2 --proxytunnel`, the SVID as the
  proxy client certificate) and sends inner HTTP/1.1 requests through them,
  which is the HBONE shape the waypoint terminates. The waypoint's server
  certificate is its SPIFFE SVID (URI SAN only), which curl cannot
  hostname-verify, so the client skips proxy server verification; every
  assertion is about what the waypoint admits and routes.

## What it asserts

Each run writes `target/mesh-e2e-service-waypoint/live-assertions.json`
(shared schema from `tests/k8s/lib/live_assertions.sh`; suite
`mesh-e2e-service-waypoint`, platform profile `kind-spire-service-waypoint`):

| Assertion | Proof |
|---|---|
| `service_waypoint.binding.bound_services_projected` | `GET /service-waypoint/services` on the waypoint names `swp` and exactly the four bound Services (required in every run, including the adoption window below) |
| `service_waypoint.status.mesh_http_routes_reported` | the split VirtualService reports `FerrumAccepted=True` with `status.ferrum.translation.mesh_http_routes: sidecar_node_and_service_waypoint` |
| `service_waypoint.virtual_service.weighted_split_90_10` | **1000** inner requests, each over its own HBONE tunnel to the `swsvc` host, all complete (curl exit 0) with 200 from a leg, with the `swsvc-v1` count in **[850, 950]** (the design's 85-95%). With `X ~ Binomial(1000, 0.9)` (sd 9.49) that is +-5.3 sd: `P(X<850)=2.8e-7`, `P(X>950)=2.8e-9`; 100/0, 50/50 and a 96/4 drift fail. The sample stops as soon as it can no longer pass |
| `service_waypoint.virtual_service.header_match_and_per_branch_authz` | all **100** `x-canary: true` requests reach `swsvc-v2`; `x-canary: true` + `x-deny: true` is refused **403** by swsvc-v2's own AuthorizationPolicy (`targetRefs` Service `swsvc-v2`, DENY on `request.headers[x-deny]`) and the waypoint's `GET /mesh/policy-denies/recent` records the deny for that policy; `x-stable: true` + `x-deny: true` is still served by `swsvc-v1` (no policy) |
| `service_waypoint.virtual_service.host_spoof_rejected` | CONNECT to `swsvc` with inner `Host: swsvc-v2...:8080` returns **403** and no backend marker |
| `service_waypoint.virtual_service.cross_namespace_reference_grant` | the `swx` VirtualService to `xsvc.beta` reports `FerrumAccepted=False` reason `RefNotPermitted` and never reaches `xsvc` without a ReferenceGrant; with a ReferenceGrant in `beta` it reports `True` and reaches `xsvc`; after deleting the grant it is refused and unreachable again |
| `service_waypoint.hbone.fence_revocation_on_binding_withdrawal` | an inner `GET /slow` on `swsvc-v1` (the backend answers after 90 s) is held over an L7 tunnel; removing `istio.io/use-waypoint` from `swsvc-v1` cuts it with `RST_STREAM(CONNECT_ERROR)` in under 80 s and moves `ferrum_mesh_hbone_tunnel_revocations_total` |
| `service_waypoint.metrics.l7_families_moved` | `ferrum_mesh_service_waypoint_l7_tunnels_active` is at least 1 while the tunnel is held; `ferrum_mesh_service_waypoint_l7_tunnel_terminations_total` moves for `reason="clean_close"` over the split sample and `reason="fence_revoked"` over the withdrawal; `ferrum_mesh_service_waypoint_route_refusals_total{reason="host_mismatch"}` moves over the spoof probe; the HBONE revocation counter moves over the withdrawal |

The fence-revocation probe runs last because it withdraws `swsvc-v1`'s
binding. All L7 probes share a 1500 s budget; every request is bounded by
`curl -m`.

## Adoption window (until #7500 / #7501 ship)

Before ServiceWaypoint L7 termination exists, the control plane reports
`mesh_http_routes: sidecar_and_node_waypoint` on every mesh-bound
VirtualService. The suite reads that as **ServiceWaypoint L7 not present**:

- with `FERRUM_SWP_E2E_ALLOW_L7_ABSENT=1` (set by the workflow during the
  adoption window only) every L7 row above is recorded as `skip` with that
  reason, never `pass`; the binding row must still pass, and the workflow gate
  reports the state as a warning;
- without the flag, the L7 rows are recorded as `fail`.

The follow-up that turns the gate on (after #7501 is on `main`) removes the
flag from the workflow, enrols the rows in `tests/conformance/ga_contract.yaml`
with artifact validation, and records the coverage in
`docs/mesh_supported_matrix.md`.

## Running

```bash
FERRUM_MESH_E2E_LIVE_ACK_DISPOSABLE=true tests/k8s/mesh_e2e_service_waypoint/run.sh
```

Requires `docker`, `kind`, `kubectl`, `curl`, `python3`, `openssl`,
`timeout`. Set `FERRUM_MESH_E2E_DEPLOY_ONLY=1` for a deploy-only smoke and
`FERRUM_SKIP_IMAGE_BUILD=1` when the runtime image is already loaded. CI runs
it from `.github/workflows/mesh-e2e-service-waypoint-live.yml`
(trusted-base relevance via `.github/scripts/live_suite_path_filter.py`, suite
`mesh-e2e-service-waypoint`); the check `Mesh E2E ServiceWaypoint Live` is
optional and is not in `.github/required-publication-checks.json`.
