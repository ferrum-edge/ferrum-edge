# Sidecar mesh live e2e suite (`mesh-e2e-sidecar`)

Live single-cluster validation of the **Stable Sidecar traffic surface** on a
real kind cluster with real SPIRE-issued SVIDs — the datapath the in-process
functional tests collapse (no iptables capture, loopback dials). One kind
cluster runs SPIRE, the hand-crafted sidecar workloads, and a Ferrum control
plane:

- **svc** — the destination: an inbound iptables init container REDIRECTs app
  port `8080 -> :15006`, a Ferrum sidecar (`FERRUM_MESH_TOPOLOGY=sidecar`,
  STRICT inbound, SPIRE identity, `FERRUM_MESH_CONFIG_PROTOCOL=file`) and a
  python echo app.
- **client** — an allowed sidecar + curl driver; its init container installs
  an `OUTPUT DROP` for a designated black-hole IP (the `slowsvc` workload
  address) so the DestinationRule connectTimeout probe times a **genuinely
  hanging** connect inside the pod's own netns, independent of cluster/host
  routing.
- **rogue** — identical to client but `sa/rogue`; it completes valid
  same-trust-domain mTLS and is then denied by the destination's
  identity-scoped AuthorizationPolicy (`mesh_authz` 403) — a
  destination-sourced negative, not an incidental client-side TLS failure.
- **wssvc** — a second destination pod with **its own identity** (`sa/wssvc`,
  distinct pod UID, so it is not folded into `sa/svc`'s inbound Host table)
  running a minimal RFC 6455 echo that answers upgrades with a correct
  `Sec-WebSocket-Accept` and **holds** the session — the target of the DR
  `maxConnections=1` probe.
- **ferrum-cp** — a Ferrum **control plane** (`FERRUM_MODE=cp`, sqlite on an
  emptyDir, namespaced RBAC only) whose K8s controller builds the mesh model
  from the cluster's **real** Services/Pods/EndpointSlices and Istio
  objects — the only path that populates a CP's mesh block. Istio CRD
  watching is on (`FERRUM_K8S_WATCH_ISTIO_CRDS=true`) for the three kinds the
  suite installs from pinned offline fixtures
  (`tests/fixtures/k8s/istio_virtualservice_crd.yaml`,
  `tests/fixtures/k8s/istio_destinationrule_crd.yaml`,
  `tests/fixtures/k8s/istio_peerauthentication_crd.yaml`), with read access in
  the watch namespace and in the Istio root namespace `istio-system`, plus
  `get`/`patch`/`update` on their `status` subresources so the controller
  writes real `FerrumAccepted` conditions. The pinned Gateway API
  `ReferenceGrant` CRD (`tests/fixtures/k8s/gateway_api_referencegrant_crd.yaml`)
  is installed and Established alongside them, but Gateway API watching stays
  off (the split gate is same-namespace). The CRD fixtures are exact paths in
  the trusted relevance filter, so a change to one runs this suite. It
  serves the mesh model over the native
  `MeshConfigSync.MeshSubscribe` gRPC stream on `:50051` with production
  **mTLS + JWT**. The CP server certificate SAN is the Kubernetes Service
  DNS hostname the DP dials (`https://ferrum-cp.<ns>.svc.cluster.local:50051`);
  `FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH` requires a DP client certificate; JWT
  remains required on the same stream. Ephemeral PKI is minted per run into a
  private temporary directory on the controller host (normally removed on
  EXIT, never copied to results/artifacts) and transferred into projected
  Secrets (`ferrum-native-mtls-cp` / `ferrum-native-mtls-dp`).
  The release-blocking native leg does not permit plaintext gRPC and does
  not skip server certificate verification.
- **capp** — a third destination pod shaped like `svc` (inbound REDIRECT
  `8080 -> :15006`, SPIRE identity `sa/capp`, python echo answering a
  distinct `-native` marker) whose sidecar runs
  `FERRUM_MESH_CONFIG_PROTOCOL=native` subscribing to `ferrum-cp` over that
  mTLS+JWT channel — **no ConfigMap**: its inbound routes exist only if the
  CP-delivered MeshSubscribe slice materialized, which is the live proof for
  the native config-transport GA row (issues #2002 / #3855). Dedicated probe
  Deployments use `sa/native-mtls-probe` (not capp) so omit-client,
  foreign-client, untrusted-server-CA, wrong-SAN, and invalid-JWT negatives
  cannot make capp's inbound resolution ambiguous. A projected Secret
  generation swap proves watched CP/DP gRPC TLS rotation reconnects without
  a pod restart; the replacement leaf serial is observed over mTLS from the
  running CP listener.
- **drsvc-a / drsvc-b** — DestinationRule visibility destinations: two
  sidecar-backed workloads (`sa/drsvc-a`, `sa/drsvc-b`, inbound REDIRECT
  `8080 -> :15006`, SPIRE, STRICT) behind MeshService `drsvc` owned by
  namespace `beta`. Labelled echo bodies (`backend-a` / `backend-b`) prove
  round-robin vs sticky DestinationRule outcomes on the captured client
  egress path. Plain ServiceEntry endpoints are intentionally not used —
  Sidecar outbound materialization only iterates MeshService workloads.
- **vs-client / vssvc-v1 / vssvc-v2 / vssvc** — the VirtualService `http[]`
  split gate (issue #7502). `vs-client` is a Sidecar **client** on
  `FERRUM_MESH_CONFIG_PROTOCOL=native` (same mTLS + JWT channel as capp,
  SPIRE identity `sa/vs-client`): the file-source clients above cannot carry
  the gateway proxies/upstreams a VirtualService `http[]` route translates
  into, so the routes reach a Sidecar only through a CP-delivered slice
  (`MeshSubscribeRequest.sidecar_http_routes`). Its init container installs
  the injector's outbound capture chain (pod-local and proxy-UID 1337
  `RETURN`s, then `REDIRECT` of all other TCP to `:15001`), so the probes dial
  `http://vssvc.<ns>.svc.cluster.local:8080/` like an application and reach
  Ferrum only through real capture. `vssvc-v1` / `vssvc-v2` are capp-shaped
  native destinations with their own identities answering `vs-backend-v1` /
  `vs-backend-v2`, made **STRICT** by a selector-scoped PeerAuthentication
  (`vs-split-backend: "true"`) that run.sh applies through the control plane
  before they start. `vssvc` is a frontend Service whose selector matches no
  pod (one pod backs exactly one Service), so the client has no plain Service
  route for it: only the carried VirtualService route can answer. run.sh
  applies the VirtualService (`x-canary: true` → `vssvc-v2`, otherwise 90/10
  `vssvc-v1`/`vssvc-v2`) as the LAST probe, after every other assertion is
  recorded, under a 900 s budget (each request bounded by `curl -m 5`; every
  sample stops as soon as it can no longer pass; a failed prerequisite records
  both rows as failed at once).

- **cross-namespace sub-fixture** (`xns_manifests.yaml`, issue #7499) — applied
  by the last probe, after every other assertion is recorded. A
  cross-namespace destination needs a control plane that serves both
  namespaces, and a multi-namespace control plane authorizes data planes only
  through a namespace-bound trust bundle; the main `ferrum-cp` is
  single-namespace and its probes depend on that, so this gate runs its own
  control plane `ferrum-cp-xns` (`FERRUM_CP_NAMESPACES=<ns>-xsrc,<ns>-xdst`, one
  HS256 trust-bundle credential `kid: xns` for both namespaces, the same
  production gRPC mTLS with its own server SAN, Istio CRD and Gateway API
  ReferenceGrant watching, namespaced RBAC in both namespaces and
  `istio-system`) in two namespaces the main control plane never watches.
  `ferrum-cp-xns` applies Sidecar egress scopes
  (`FERRUM_MESH_SIDECAR_ENFORCED=true`). `<ns>-xsrc` holds the native Sidecar
  client `xclient` (outbound capture, an externally minted bearer whose `ns`
  claim names both namespaces, presented through
  `FERRUM_DP_CP_GRPC_TOKEN_FILE`), the local split leg `xlocal`, the unbacked
  frontend Service `xfront`, the VirtualService and a namespace `Sidecar`
  importing `<ns>-xdst/*` (CRD `istio_sidecar_crd.yaml` in this directory,
  installed with the other CRDs; the main control plane's Roles grant
  `sidecars` too). `<ns>-xdst` holds the destination `xremote`, its
  DestinationRule and the ReferenceGrant from `networking.istio.io/VirtualService`
  in `<ns>-xsrc` to Service `xremote`. Bounded by a 900 s budget.

## What it asserts

Each run writes `target/mesh-e2e-sidecar/live-assertions.json` using the
shared schema from `tests/k8s/lib/live_assertions.sh` (suite
`mesh-e2e-sidecar`, platform profile `kind-spire-sidecar`) and gates on:

| Assertion | Proof |
|---|---|
| `sidecar.spire.workload_entries` | svc/wssvc/client/rogue/capp/native-mtls-probe/drsvc-a/drsvc-b/vs-client/vssvc-v1/vssvc-v2 SPIRE entries registered |
| `sidecar.peer_auth.strict_mtls_authenticated` | captured client request → mesh-mTLS → STRICT inbound → 200 with the app marker |
| `sidecar.peer_auth.strict_mtls_plaintext_rejected` | plaintext dial at the **captured** app port never reaches the app (REDIRECT → STRICT rejects) |
| `sidecar.authz.denied_principal_rejected` | rogue → 403 with `Mesh authorization denied` (dest-side `mesh_authz`) |
| `sidecar.request_auth.valid_jwt_admitted` | RS256 JWT validated against the RequestAuthentication **inline JWKS** → 200 |
| `sidecar.request_auth.missing_jwt_rejected` | token-less request on the gated path → 403 (RequestAuth is permissive; the authz `request_principals` ALLOW does not match) |
| `sidecar.request_auth.invalid_jwt_rejected` | wrong-key signature → 401 `Invalid or unrecognized JWT` (`jwks_auth`) |
| `sidecar.destination_rule.export_to_namespace_visibility` | captured client egress to a `beta`-owned MeshService (`drsvc`) with two labelled sidecar backends: a service-namespace sticky rule `exportTo: [.]` leaves round-robin (both backends), while an exported root-namespace sticky control pins one backend |
| `sidecar.destination_rule.lookup_tier_client_wins` | three visible rules at client, service, and root tiers on that same live host; the client-tier round-robin rule wins over sticky lower-priority rules (both backends serve) |
| `sidecar.destination_rule.tcp_connect_timeout` | two-phase timing: the black-holed mesh-mTLS dial fails at ~8s under `connect_timeout_ms: 8000`, then ~2s after a re-render + rollout restart to `2000` — the observed time must **track** the configured value (both windows exclude the built-in 5000ms default) |
| `sidecar.virtual_service.cors_policy` | VS-derived CORS on the client sidecar: allowed `Origin` → backend 200 with the origin reflected, allowed `OPTIONS` preflight → **200 by the sidecar** with `access-control-allow-methods`, and unmatched actual/preflight requests → backend 200 with the app marker and no gateway-added `access-control-allow-origin` (Istio omitted/FORWARD semantics) |
| `sidecar.virtual_service.weighted_split_90_10` | a `kubectl`-applied VirtualService reports `FerrumAccepted=True` with `status.ferrum.translation.mesh_http_routes: sidecar_and_node_waypoint`; both split destinations refuse a TLS client that presents no certificate (curl fails at the TLS layer with no HTTP status), so they are STRICT and every counted answer required `vs-client`'s SVID; the route converges; and **1000** captured requests to `http://vssvc.<ns>.svc.cluster.local:8080/` all complete (curl exit 0) with 200 from a leg, with the `vssvc-v1` count in **[850, 950]** (the design's 85–95%). With `X ~ Binomial(1000, 0.9)` (sd 9.49) that window is ±5.3 sd: a correct split fails with probability ~2.8e-7 (`P(X<850)=2.8e-7`, `P(X>950)=2.8e-9`), while 100/0 (`X=1000`, no v2 marker), 50/50, and a 96/4 drift fail. Ferrum's leg selection is a deterministic weighted round robin, so real runs land within a few requests of 900 |
| `sidecar.virtual_service.header_match_dispatch` | all **100** `x-canary: true` requests complete with 200 from `vssvc-v2` (an ignored rule would follow the split: 0.1^100), and **1000** `x-canary: false` requests fall through to the split inside the same **[850, 950]** `vssvc-v1` window (a route pinned to either leg fails) |
| `sidecar.virtual_service.cross_namespace_direct_destination` | issue #7499, on the cross-namespace sub-fixture below: the VirtualService in `<ns>-xsrc` reports `FerrumAccepted=True` and lists `<ns>-xdst/xremote` in `status.ferrum.translation.cross_namespace_destinations`, and all **20** captured `xclient` requests to the carried direct route (`http://xfront.<ns>-xsrc.svc.cluster.local:8080/direct`, a Service no pod backs) complete with 200 from `xremote` in the other namespace |
| `sidecar.virtual_service.cross_namespace_weighted_split_leg` | the same VirtualService's 50/50 split `xlocal` (`<ns>-xsrc`) / `xremote` (`<ns>-xdst`), whose remote leg a DestinationRule in `<ns>-xdst` governs: all **400** captured requests complete with 200 from a leg and the `xlocal` count is in **[150, 250]** (±5 sd of Binomial(400, 0.5); a leg pinned to either side fails) |
| `sidecar.virtual_service.cross_namespace_grant_withdrawal_refused` | after the ReferenceGrant is deleted the VirtualService turns `FerrumAccepted=False` / `RefNotPermitted`, none of **20** captured requests to the withdrawn route answers from a leg, and the client's ordinary `xlocal` Service route still answers 200 (the rest of the slice keeps serving) |
| `sidecar.destination_rule.tcp_max_connections` | WebSocket flow (`wssvc`, maxConnections=1): one **held** WS session admitted (101), a concurrent second upgrade rejected **503** by the client sidecar's `BackendConnectionGuard` before dialing, and a fresh upgrade admitted after the held session closes — cap enforcement **and** release |
| `sidecar.config.native_subscribe_delivered` | native MeshSubscribe delivery over production mTLS + JWT (issues #2002 / #3855): a captured client request to `capp` answers 200 with the `-native` marker — capp's inbound routes exist **only** if the ferrum-cp MeshSubscribe stream delivered a slice whose K8s-built `sa/capp` workload resolved locally — **and** capp's JWT-authenticated `GET /mesh/config-drift` reports a received slice with `source_protocol=native` from the `https://ferrum-cp...` URL and ≥1 service |
| `sidecar.config.native_subscribe_mtls_omitted_client_rejected` | dedicated probe DP omits its client certificate; MeshSubscribe never accepts a slice |
| `sidecar.config.native_subscribe_mtls_foreign_client_rejected` | dedicated probe DP presents a client certificate from a foreign CA; no slice accepted |
| `sidecar.config.native_subscribe_tls_untrusted_server_ca_rejected` | dedicated probe DP trusts the wrong server CA; no slice accepted |
| `sidecar.config.native_subscribe_tls_wrong_san_rejected` | dedicated probe DP dials `ferrum-cp-wrong-san.<ns>.svc.cluster.local`, a hostname absent from the CP server SAN; no slice accepted |
| `sidecar.config.native_subscribe_jwt_rejected` | dedicated probe DP completes mTLS then presents an invalid JWT; no slice accepted |
| `sidecar.config.native_subscribe_tls_rotation_reconnects` | projected Secret generation swap of CP/DP gRPC TLS material reconnects the native stream without a pod restart; after the pre-swap baseline the production `capp` DP must publish a successful `surface=dp_grpc` TLS reload and then emit a Connected-to-CP for that exact pod/node identity, and the CP must publish a successful `surface=cp_grpc` TLS reload and then emit a `Tenant subscription accepted` audit for that same identity, strictly newer than the pre-swap baseline and ordered after those reload anchors (reload logs are not proof by themselves); an over-the-wire mTLS handshake to the running CP (Service DNS SAN, gen2 server CA, gen2 DP client cert) observes the replacement leaf serial, and a gen-1 client is then rejected |

The rotation probe fetches the original `capp` pod's current `ferrum-edge`
container logs with `kubectl logs --prefix=true --tail=-1`. The application
continues withholding its configured `node_id`; the classifier binds redacted
connection events to the exact `[pod/<name>/ferrum-edge]` source prefix instead.
Another pod or container, an unbound placeholder, or a conflicting visible
node ID cannot supply client evidence. The CP must still accept that exact
node ID after its own TLS reload, and both event histories must retain the
pre-swap baseline.

Every assertion backs a contract capability row in
`tests/conformance/ga_contract.yaml` — STRICT mTLS, AuthorizationPolicy
allow/deny, RequestAuthentication JWT, DR namespace visibility/lookup precedence, DR connectTimeout, DR maxConnections,
VirtualService CORS, SPIFFE identity plumbing
(`mesh.identity.spire_svid_issuance`, backed by
`sidecar.spire.workload_entries` plus the SVID-carried
`sidecar.peer_auth.strict_mtls_authenticated` positive, which that row shares
with the PeerAuthentication row), and the native MeshSubscribe config
transport (`mesh.config_transport.native_subscribe`, backed by
`sidecar.config.native_subscribe_delivered` plus the mTLS/JWT/SAN negatives
and projected-Secret rotation assertions); the artifact is validated
against the contract by `tests/conformance/live_contract.rs` (the live
workflow runs it right after the fixture). The two `sidecar.virtual_service.*`
split-gate assertions back the **Experimental** row
`mesh.virtual_service.sidecar_http_routes`: they are enforced exactly like
the GA rows (live validation covers every non-deferred row whatever its
maturity), but VirtualService `http[]` routing on a Sidecar is not a GA
promise until an owner-reviewed promotion. No contract row for this suite is
`live_deferred`.

This contract is **PR- and release-blocking**: the dedicated workflow's
`Mesh E2E Sidecar Live` gate job is a branch-protection required check
directly (there is no mirror job in `ci.yml`), the suite force-runs on
every main push, and `release.yml`'s `validate-release-sha` requires it (via
`.github/required-publication-checks.json`) to be green for the tag target
before anything ships.

## JWT material

RS256 keys are generated fresh per run with `openssl`; python3 stdlib
assembles the base64url JWKS/tokens (no pip installs). The invalid-token
probe signs with a second key under the **same kid/issuer**, so it selects
the published JWKS key and fails precisely on signature verification.

Separately, run.sh mints two per-run HS256 secrets into the
`ferrum-mesh-e2e-secrets` Secret: the CP↔DP gRPC JWT secret
(`FERRUM_CP_DP_GRPC_JWT_SECRET`, the DP self-mints its bearer from it) and a
shared admin-API secret (`FERRUM_ADMIN_JWT_SECRET` on ferrum-cp and the capp
sidecar). The admin API validates but never mints, so run.sh signs the
`/mesh/config-drift` bearer itself (python3 stdlib HMAC, all six required
claims + `role`); the curl runs inside the capp pod because the admin API
binds loopback.

## Reload model

The Ferrum runtime image is distroless (no shell, no `kill`), so mesh config
changes are applied by `kubectl rollout restart` — the replacement pod reads
the updated ConfigMap at startup. The two-phase DR probe re-settles the
positive route after the restart before timing phase 2.

## Running

```bash
FERRUM_MESH_E2E_LIVE_ACK_DISPOSABLE=true tests/k8s/mesh_e2e_sidecar/run.sh
```

Requires `docker`, `kind`, `kubectl`, `curl`, `python3`, `openssl`. Set
`FERRUM_MESH_E2E_DEPLOY_ONLY=1` for a local deploy-only smoke (SPIRE/workload
rollout, no traffic probes). `FERRUM_SKIP_IMAGE_BUILD=1` when the runtime image is
prebuilt/loaded. CI coverage is the full datapath run in
`.github/workflows/mesh-e2e-sidecar-live.yml` (path-filtered via
`.github/scripts/live_suite_path_filter.py`, suite `mesh-e2e-sidecar`); the
required check is `Mesh E2E Sidecar Live`.
