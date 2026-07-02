# Sidecar mesh live e2e suite (`mesh-e2e-sidecar`)

Live single-cluster validation of the **Stable Sidecar traffic surface** on a
real kind cluster with real SPIRE-issued SVIDs — the datapath the in-process
functional tests collapse (no iptables capture, loopback dials). One kind
cluster runs SPIRE plus three hand-crafted sidecar workloads:

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
- **wssvc** — a second destination pod (`sa/wssvc`, **its own identity**: one
  local pod backs exactly one service, so the WS listener must not be a
  second local `service_name` on `sa/svc` — `resolve_local_workloads` fails
  closed on that ambiguity and materializes no inbound routes) running a
  minimal RFC 6455 echo that answers upgrades with a correct
  `Sec-WebSocket-Accept` and **holds** the session — the target of the DR
  `maxConnections=1` probe.

## What it asserts

Each run writes `target/mesh-e2e-sidecar/live-assertions.json` using the
shared schema from `tests/k8s/lib/live_assertions.sh` (suite
`mesh-e2e-sidecar`, platform profile `kind-spire-sidecar`) and gates on:

| Assertion | Proof |
|---|---|
| `sidecar.spire.workload_entries` | svc/client/rogue SPIRE entries registered |
| `sidecar.peer_auth.strict_mtls_authenticated` | captured client request → mesh-mTLS → STRICT inbound → 200 with the app marker |
| `sidecar.peer_auth.strict_mtls_plaintext_rejected` | plaintext dial at the **captured** app port never reaches the app (REDIRECT → STRICT rejects) |
| `sidecar.authz.denied_principal_rejected` | rogue → 403 with `Mesh authorization denied` (dest-side `mesh_authz`) |
| `sidecar.request_auth.valid_jwt_admitted` | RS256 JWT validated against the RequestAuthentication **inline JWKS** → 200 |
| `sidecar.request_auth.missing_jwt_rejected` | token-less request on the gated path → 403 (RequestAuth is permissive; the authz `request_principals` ALLOW does not match) |
| `sidecar.request_auth.invalid_jwt_rejected` | wrong-key signature → 401 `Invalid or unrecognized JWT` (`jwks_auth`) |
| `sidecar.destination_rule.tcp_connect_timeout` | two-phase timing: the black-holed mesh-mTLS dial fails at ~8s under `connect_timeout_ms: 8000`, then ~2s after a re-render + rollout restart to `2000` — the observed time must **track** the configured value (both windows exclude the built-in 5000ms default) |
| `sidecar.destination_rule.tcp_max_connections` | WebSocket flow (`wssvc`, maxConnections=1): one **held** WS session admitted (101), a concurrent second upgrade rejected **503** by the client sidecar's `BackendConnectionGuard` before dialing, and a fresh upgrade admitted after the held session closes — cap enforcement **and** release |

Every assertion except `sidecar.spire.workload_entries` (fixture
infrastructure) backs a GA-contract capability row in
`tests/conformance/ga_contract.yaml` — STRICT mTLS, AuthorizationPolicy
allow/deny, RequestAuthentication JWT, DR connectTimeout, and DR
maxConnections; the artifact is validated against the contract by
`tests/conformance/live_contract.rs` (the live workflow runs it right after
the fixture). The one remaining `live_deferred` contract id is VS CORS
(issue #1973 — the mesh slice carries no VirtualService-derived route
plugins).

## JWT material

RS256 keys are generated fresh per run with `openssl`; python3 stdlib
assembles the base64url JWKS/tokens (no pip installs). The invalid-token
probe signs with a second key under the **same kid/issuer**, so it selects
the published JWKS key and fails precisely on signature verification.

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
`FERRUM_MESH_E2E_DEPLOY_ONLY=1` for the deploy-only smoke (the `ci.yml`
`mesh-e2e-sidecar` job), `FERRUM_SKIP_IMAGE_BUILD=1` when the runtime image is
prebuilt/loaded. The full datapath run rides
`.github/workflows/mesh-e2e-sidecar-live.yml` (path-filtered via
`.github/scripts/live_suite_path_filter.py`, suite `mesh-e2e-sidecar`).
