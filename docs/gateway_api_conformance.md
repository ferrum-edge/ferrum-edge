# Gateway API Conformance

This is the **canonical reference** for Ferrum's upstream Gateway API
conformance workflow — the single source of truth for its **gating status,
claimed profiles/features, listener-status emission, data-plane coverage, and
uploaded artifacts.** The repo-root [`CONFORMANCE.md`](../CONFORMANCE.md) is a
conformance index that links here and additionally owns the in-process
Istio + xDS compatibility suite. Keep workflow facts here; do not restate them
in `CONFORMANCE.md`.

## Workflow, triggers, and gating

The standalone `.github/workflows/gateway-api-conformance.yml` workflow is the
authoritative Gateway API conformance check, and it **gates** merges:

- **Triggers:** `pull_request`, `push` to `main`, a weekly `schedule`
  (Mondays 07:00 UTC), and manual `workflow_dispatch` (whose inputs are
  `gateway_api_version`, `conformance_profile`, `supported_features`, and
  `skip_tests`). A lightweight `changes` job (path filter via
  `.github/scripts/live_suite_path_filter.py --suite gateway-api`) runs first
  and skips the ~90-minute lab unless the PR touches routing, Kubernetes
  translation/status, CP/DP sync, data-plane startup, plugins, charts, the
  runtime image, proto, the conformance script, dependencies, or related CI.
- **Gating:** the workflow's `gate` job fails the check when change detection,
  the upstream suite, or the black-box checks fail (a lab skipped on an
  irrelevant PR passes). Separately, `ci.yml`'s
  `Gateway API Conformance (CI mirror)` job mirrors this workflow's conclusion
  into the aggregate `Tests` gate as a `require_success`, so a red conformance
  run also reds main CI. The workflow is **not** advisory.

## Default run parameters

| Parameter | Value |
|---|---|
| Gateway API version | `v1.5.1` |
| Conformance profile | `GATEWAY-HTTP` |
| Supported features | `Gateway,ReferenceGrant,HTTPRoute` |
| GatewayClass | `ferrum` |
| Controller name | `ferrum.io/gateway-controller` |

Kick a manual run with:

```bash
gh workflow run "Gateway API Conformance" \
  --field gateway_api_version=v1.5.1 \
  --field conformance_profile=GATEWAY-HTTP \
  --field supported_features=Gateway,ReferenceGrant,HTTPRoute
```

## Independent Validation

Baseline commit inspected before remediation: `1252246777bdaa8fcbe6b401ffdc9020d7f71e11` (`12522467 Merge pull request #1826 from ferrum-edge/codex/dr-proxy-route-rebuild`).

The previous `.github/workflows/gateway-api-conformance.yml` defaulted to Gateway API `v1.5.1`, advertised `Gateway,HTTPRoute`, and ran only these upstream tests:

- `GatewayClassObservedGenerationBump`
- `GatewayObservedGenerationBump`
- `HTTPRouteObservedGenerationBump`
- `HTTPRouteInvalidCrossNamespaceParentRef`

Manual dispatch of that workflow on `main` succeeded in run `27799052406` on June 19, 2026. The artifact showed only the control-plane deployment and Service in the `ferrum` namespace. No Ferrum data-plane deployment, pod, listener Service, NodePort, or LoadBalancer was installed. The upstream JSON marked request-path tests such as `HTTPRouteSimpleSameNamespace`, `HTTPRouteWeight`, and `HTTPRouteReferenceGrant` as skipped, and there were no client request traces against a Ferrum listener. That run therefore validated status/controller behavior only; it did not prove data-plane conformance.

Follow-up validation on branch `codex/gateway-api-data-plane-conformance` reached the Ferrum data plane and exposed real request-path gaps: invalid `backendRefs` returned 404 instead of the Gateway API fail-closed 500, Gateway listener `certificateRefs` were status-checked but not applied to the serving DP certificate, `RequestHeaderModifier` and `RequestRedirect` were incomplete, and selectorless/headless Services backed only by EndpointSlices did not resolve to routable backends. Those gaps are now covered by translator/status unit tests plus the direct black-box lab checks.

## Supported-Feature Matrix

| Gateway API surface | Claimed in CI | Current Ferrum behavior |
|---|---:|---|
| `GatewayClass` | Yes | Watched and status-patched for `ferrum.io/gateway-controller` |
| `Gateway` HTTP listeners | Yes | Translated into Ferrum HTTP listener materialization; listener status and `Programmed` are patched |
| `Gateway` HTTPS listeners | Yes, as part of `GATEWAY-HTTP` | Terminating listeners materialize `certificateRefs` into namespace-scoped DP frontend TLS sources and the DP rejects snapshots if the referenced serving cert/key cannot be loaded |
| `HTTPRoute` hostname, path, method, header, and query matching | Yes | Translated into proxies plus ordered `mesh_route_dispatch` rules where predicate matching is needed |
| `HTTPRoute` `RequestHeaderModifier` | Yes | Route-level set/add/remove header filters are projected into request-transform rules and verified by black-box backend echo |
| `HTTPRoute` `RequestRedirect` | Yes | Redirect filters materialize action-only dispatch rules with status, hostname, scheme, port, and path replacement support |
| `HTTPRoute` weighted `backendRefs` | Yes | Multiple non-zero backends create a weighted upstream; a rule whose backendRefs are **all** `weight: 0` fails closed through a blackhole backend (~502, a known divergence from the spec's 500) — see [backendRef port and zero-weight semantics](#backendref-port-and-zero-weight-semantics) |
| Cross-namespace `HTTPRoute.backendRefs` | Yes | Requires an exact `ReferenceGrant`; missing grants are rejected and unresolved |
| Cross-namespace `parentRefs` | Yes | Allowed only when the referenced Gateway listener permits the route namespace |
| Invalid backend references | Yes | Missing Services, unsupported backend target kinds, and unpermitted cross-namespace refs are reported as unresolved and materialize fail-closed HTTP 500 routes |
| Selectorless/headless Services | Yes | With pod discovery enabled, backends resolve ready EndpointSlice addresses directly; a named Service `targetPort` resolves against EndpointSlice port names, but the `backendRef.port` itself is numeric-only — see [backendRef port and zero-weight semantics](#backendref-port-and-zero-weight-semantics) |
| Backend failure | Yes | Traffic to unavailable generated backends must return an error response rather than falling through |
| Route update and deletion | Yes | Reconciliation regenerates live proxy/upstream/plugin config; deletion removes the route from live config |
| `GRPCRoute` | Not claimed by the `GATEWAY-HTTP` gate | Watched and partially translated through HTTP/gRPC routing, but not advertised as a passing upstream `GATEWAY-GRPC` profile until request traffic conformance is added |
| `TLSRoute` and `TCPRoute` | Not claimed | Watched/translated for L4 experiments, but not advertised as supported Gateway API conformance profiles |
| `UDPRoute`, `BackendTLSPolicy`, `ListenerSet`, `BackendLBPolicy` | No | Not claimed as effective Gateway API conformance features |

## backendRef port and zero-weight semantics

These behaviors are exercised by the black-box lab (invalid and weighted refs)
and specified field-by-field in [`docs/configuration.md`](configuration.md)
(Kubernetes Mesh Integration — the authoritative field-level reference). They
are summarized here because they are common conformance questions. Open
residuals are tracked in
[#2027](https://github.com/ferrum-edge/ferrum-edge/issues/2027) (single-cluster
Gateway API backendRef residuals) — **not** in the cross-cluster/UDP mesh
trackers (#2010, #2013).

- **Invalid / unresolved backendRef** (missing Service, unsupported backend
  kind, or an unpermitted cross-namespace ref) materializes a fail-closed route
  that returns **HTTP 500**, matching the Gateway API expectation. The
  black-box lab asserts the `/invalid` route returns `500`.
- **Zero-weight-only rule** (every `backendRef` in a matched rule has
  `weight: 0`) is *not* dropped — Ferrum emits a generated
  `ferrum-zero-weight.invalid:65535` blackhole backend so the rule still
  captures traffic instead of falling through to a broader later route. That
  blackhole currently fails as a **backend/DNS-resolution failure (typically a
  502)**, a **known divergence** from the spec's expected 500 for a rule with no
  serviceable backends (tracked in #2027). Translator unit tests
  (`http_route_keeps_all_zero_weight_rule_as_blackhole`) assert the generated
  backend *shape*; the request-time status is not yet asserted in-tree.
- **backendRef port is numeric-only.** A Gateway API `backendRef.port` must be a
  number; naming a Service port from a `backendRef`
  (`Service.spec.ports[].name`) is **not implemented** for Gateway API
  translation (Istio `VirtualService` destinations *do* support `port.name`).
  Once a numeric backendRef port has selected a Service port, that Service's
  `targetPort` **may** be a named pod port — resolved against EndpointSlice port
  names. That Service-`targetPort` resolution is currently unit-tested only for
  numeric target ports on the Gateway API path (tracked in #2027).

## CI Evidence

The standalone `gateway-api-conformance.yml` workflow is the single owner that deploys the lab on PRs, and its `gate` job is the authoritative conformance check. The `Gateway API Conformance (CI mirror)` job in `ci.yml` only mirrors that run's result back into the aggregate `Tests` gate. The lab consists of:

- Ferrum control plane/controller with Gateway API watches enabled.
- A routable Ferrum data-plane deployment and NodePort Service mapped to host ports 80 and 443 in kind.
- Two HTTP echo backend namespaces.
- `GatewayClass`, `Gateway`, `HTTPRoute`, `GRPCRoute`, and `ReferenceGrant` resources for direct black-box checks.
- The upstream Gateway API conformance suite pinned by `GATEWAY_API_VERSION`, defaulting to `v1.5.1`, running the complete `GATEWAY-HTTP` profile with explicit supported features `Gateway,ReferenceGrant,HTTPRoute`.

Direct black-box checks cover hostname, path, method, headers, weighted backend selection, cross-namespace references, invalid references, backend failure, TLS, route updates, and route deletion. Diagnostics and the upstream standard conformance report are uploaded from `conformance-results/` as retained CI artifacts.

The standalone Gateway API conformance workflow triggers on every PR, but a lightweight `changes` job gates the heavy lab job internally: it runs the conformance suite only when the PR diff touches routing, Kubernetes translation/status, CP/DP sync, data-plane startup, plugins, charts, the conformance script, or related CI files, and otherwise skips it. Artifacts are retained for 90 days so the standard upstream report can be reproduced from the workflow inputs and preserved as release evidence.

## Status emission scope

Ferrum's Kubernetes controller patches Gateway API status across every level the
`GATEWAY-HTTP` profile exercises:

| Surface | Status |
|---|---|
| GatewayClass status (`Accepted`, `SupportedVersion`) | Emitted |
| Gateway top-level status (`Accepted`, `Programmed`, `ResolvedRefs`, `Conflicted`) | Emitted |
| Gateway listener-level status (`status.listeners[].conditions`, `attachedRoutes`, `supportedKinds`) | **Emitted** — `attachedRoutes` is a computed count and `supportedKinds` is derived from listener protocol + `allowedRoutes.kinds` |
| Gateway `status.addresses` | Emitted when `FERRUM_GATEWAY_API_STATUS_ADDRESS` is set |
| HTTPRoute / GRPCRoute parent status (`Accepted`, `ResolvedRefs`, `Programmed`, `Conflicted`) | Emitted |
| TLSRoute / TCPRoute parent status | Emitted for watched L4 routes |

`Programmed=True` on a Gateway is additionally gated on the serving data-plane
Service having a ready EndpointSlice endpoint when
`FERRUM_GATEWAY_API_DATA_PLANE_SERVICE_NAMESPACE`/`_NAME` are set; otherwise it
reflects translation/materialization only.

### Condition reasons that diverge from the upstream constants table

Ferrum emits a few reasons/condition-types that are not in the v1 spec's
enumerated constants. Custom reasons are permitted by the spec, but tooling that
asserts exact upstream strings will see them as unexpected:

| Condition | Ferrum reason | Closest upstream reason | Notes |
| --- | --- | --- | --- |
| Gateway `Programmed=False` | `NoListeners` | `NoResources` / `Pending` | Set when translation accepted the Gateway but produced no materialised listener. |
| Gateway `Programmed=False` / `ResolvedRefs=False` | `TranslationFailed` | `Invalid` | Generic translation error surface. |
| Gateway `Conflicted` (condition type) | n/a | Not in `GatewayConditionType` | Custom Ferrum extension; the upstream constants set is `Accepted` / `Programmed` / `Ready`. |
| Route `Programmed` (condition type) | n/a | Not in `RouteConditionType` | Custom Ferrum extension; the upstream constants set is `Accepted` / `ResolvedRefs` / `PartiallyInvalid`. |
| Route `Accepted=True` + `Programmed=False` | `NoRules` | `Pending` | Set when translation accepted the route but produced no materialised rule. |

These divergences are intentional. Tooling that pins exact upstream reason
strings should allowlist them; the `GATEWAY-HTTP` profile itself asserts
condition **status**, not custom reason strings.

## Artifacts

Each run uploads a `gateway-api-conformance-<version>` bundle from
`conformance-results/` (90-day retention), produced by
`scripts/gateway_api_data_plane_conformance.sh diagnostics`:

| File | What it is |
| --- | --- |
| `gateway-api-conformance-test.json` | Streaming `go test -json` events for every upstream conformance test. |
| `gateway-api-conformance-report.yaml` | Upstream `conformance.gateway.networking.k8s.io` report; `profiles[].coreTests` has pass/fail per test. |
| `gateway-api-blackbox.md` | Results of the direct black-box traffic checks (host/method/header/modifier/cross-namespace/redirect/weighted/invalid-500/no-endpoints/update/delete/TLS). |
| `gateway-api-resources.yaml` | `kubectl get gatewayclasses,gateways,httproutes,grpcroutes,referencegrants -A -o yaml` snapshot. |
| `kubernetes-workloads.txt`, `namespaces.txt`, `ferrum-*-deployment.txt`, `ferrum-pods.txt`, `ferrum-events.txt` | Cluster/workload diagnostics. |
| `ferrum-control-plane.log`, `ferrum-control-plane-previous.log`, `ferrum-data-plane.log`, `blackbox-*.log` | Container logs. |
| `CONFORMANCE.md` (run-local) | Per-run metadata (version, profile, features, data-plane Service, artifact list). Generated by the script — distinct from the repo-root [`CONFORMANCE.md`](../CONFORMANCE.md). |

## In-process Istio + xDS suite

The second compatibility surface — Istio `networking.istio.io` /
`security.istio.io` CRDs plus the xDS type URLs Ferrum subscribes to — is
covered by the in-process `tests/conformance/` suite, documented under
[Istio + xDS Conformance Suite](../CONFORMANCE.md#istio--xds-conformance-suite)
in the repo-root conformance index.
