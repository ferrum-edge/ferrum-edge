# Gateway API Conformance

Ferrum tracks Gateway API conformance through the `Gateway API Conformance` GitHub Actions workflow. The workflow installs the upstream Gateway API CRDs, deploys the Ferrum mesh controller into a `kind` cluster using the chart's control-plane RBAC, creates a Ferrum-managed `GatewayClass`, runs the upstream `go test ./conformance -run TestConformance` suite, and uploads the JSON test event stream plus the generated conformance report as workflow artifacts.

## Default run parameters

- Gateway API version: `v1.5.1`
- GatewayClass: `ferrum`
- Controller name: `ferrum.io/gateway-controller`
- Supported features: `Gateway,HTTPRoute`
- Conformance profile: `GATEWAY-HTTP`

## Triggering a run

The workflow is `workflow_dispatch` plus weekly `schedule` (Mondays 07:00 UTC) — no push or pull-request trigger. To kick a run manually:

```bash
gh workflow run "Gateway API Conformance" \
  --field gateway_api_version=v1.5.1 \
  --field supported_features=Gateway,HTTPRoute
```

A `concurrency:` group serialises manual and scheduled runs so they don't race on the same kind cluster name.

## Non-gating today

The workflow is intentionally non-gating while the Gateway API implementation is still converging. A non-zero upstream conformance exit emits a GitHub Actions `::warning::` annotation and is recorded in the uploaded run summary instead of failing the job. Infrastructure failures (control plane never reaches Ready, etc.) still fail the job — only the upstream conformance pass/fail rate is treated as advisory.

## Reading the report

Each run uploads a `gateway-api-conformance-<version>` artifact bundle containing:

| File | What it is |
| --- | --- |
| `gateway-api-conformance-test.json` | Streaming `go test -json` events for every conformance test. |
| `gateway-api-conformance-report.yaml` | Upstream `conformance.gateway.networking.k8s.io/v1alpha1` report. Scroll to `profiles[].coreTests` for pass/fail per test name; failures carry the upstream test description and assertion output. |
| `gateway-api-resources.yaml` | `kubectl get gatewayclasses,gateways,httproutes,grpcroutes -A -o yaml` snapshot. |
| `ferrum-namespace.txt` | `kubectl -n ferrum get all -o wide` snapshot. |
| `ferrum-control-plane.log` | Last 1000 lines of the control-plane container logs. |
| `CONFORMANCE.md` (run-local) | Run metadata, exit code, and artifact pointer summary. |

## Scope

| Surface | Status |
| --- | --- |
| GatewayClass status (`Accepted`, `SupportedVersion`) | Implemented. |
| Gateway top-level status (`Accepted`, `Programmed`, `ResolvedRefs`, `Conflicted`) | Implemented. |
| Gateway listener-level status (`status.listeners[].conditions`, `attachedRoutes`, `supportedKinds`) | Not yet emitted — upstream listener-level conformance assertions will fail. |
| HTTPRoute / GRPCRoute parent status (`Accepted`, `ResolvedRefs`, `Programmed`, `Conflicted`) | Implemented. |
| TLSRoute / TCPRoute status | Watched but not yet emitted. |
| Data-plane request-path conformance (`HTTPRouteSimpleSameNamespace`, `HTTPExactPathMatching`, …) | Workflow only deploys the control plane, so request-routing tests have no listener to dial and will fail until a data plane is also brought up in the test cluster. |

## Condition reasons that diverge from the upstream constants table

Ferrum emits a small set of reasons that are not in the v1 spec's enumerated constants. Custom reasons are permitted by the spec, but tooling that asserts exact upstream strings will see them as unexpected:

| Condition | Ferrum reason | Closest upstream reason | Notes |
| --- | --- | --- | --- |
| Gateway `Programmed=False` | `NoListeners` | `NoResources` / `Pending` | Set when translation accepted the Gateway but produced no materialised listener. |
| Gateway `Programmed=False` / `ResolvedRefs=False` | `TranslationFailed` | `Invalid` | Generic translation error surface. |
| Gateway `Conflicted` (condition type) | n/a | Not in `GatewayConditionType` | Custom Ferrum extension; the upstream constants set is `Accepted` / `Programmed` / `Ready`. |
| Route `Programmed` (condition type) | n/a | Not in `RouteConditionType` | Custom Ferrum extension; the upstream constants set is `Accepted` / `ResolvedRefs` / `PartiallyInvalid`. |
| Route `Accepted=True` + `Programmed=False` | `NoRules` | `Pending` | Set when translation accepted the route but produced no materialised rule. |

These divergences are intentional in the scaffolding phase. They will narrow as Ferrum's coverage of the upstream conditions table grows and the workflow flips to gating.

# Istio + xDS Conformance Suite

In addition to the Gateway API workflow above, Ferrum ships an in-process
conformance test suite at `tests/conformance/` that exercises the
Istio CRD + xDS ADS surface end-to-end and emits an auto-generated
compatibility matrix operators can use to decide "is this Istio config
supported by Ferrum Edge?".

The Gateway API workflow is for upstream `gateway.networking.k8s.io`
conformance. The Istio suite documented here covers the second
compatibility surface — Istio `networking.istio.io` / `security.istio.io`
CRDs plus the xDS type URLs Ferrum subscribes to.

## What the Istio suite covers

- **`istio_virtual_service`** — `uri.{exact,prefix,regex}`, `headers.X.*`,
  `method.*`, `authority`, `sourceNamespace`, `ignoreUriCase`,
  `queryParams.X.*`, and route-local `fault`.
- **`istio_authorization_policy`** — empty-rule semantics (`ALLOW` /
  `DENY` / `AUDIT` with no `rules`), DENY-beats-ALLOW evaluation order,
  `RequestMatch` conjunctive negative-match arms, scope translation.
- **`istio_destination_rule`** — `trafficPolicy.connectionPool.{tcp,http}`
  with both the supported and the deferred field sets, outlier detection,
  load balancers (simple + consistent hash), TLS modes (`SIMPLE`,
  `ISTIO_MUTUAL`), `portLevelSettings`, and subset overrides.
- **`istio_peer_authentication`** — single-winner precedence
  (`WorkloadSelector > Namespace > MeshWide`), `mtls.mode` translation
  (`STRICT` / `PERMISSIVE` / `DISABLE`), per-port overrides.
- **`istio_service_entry_egress`** — `location: MESH_EXTERNAL` vs
  `MESH_INTERNAL`, HTTP-family + stream-family egress materialization
  (T5-A, PR #907), `outboundTrafficPolicy: REGISTRY_ONLY` injection
  (T5-B, PR #893), hostname normalization.
- **`xds_type_urls`** — every type URL Ferrum subscribes to in
  `XDS_TYPE_URLS` (CDS, EDS, LDS, RDS, SDS, ECDS, RTDS) plus the ECDS
  DR-carrier inner
  `type.googleapis.com/ferrum.config.extension.v3.DestinationRuleCarrier`
  recognition path and the RTDS consumer keyspace
  (`ferrum.fault_injection.*`, `ferrum.{request,response}_transformer.*`,
  `ferrum.log.level`).
- **`mesh_topology_matrix`** — every mesh topology (`Sidecar`, `Ambient`,
  `NodeWaypoint`, `ServiceWaypoint`, `EastWestGateway`, `EgressGateway`)
  boots from a minimal config; `terminates_hbone` classification invariant.

## How to run

```bash
cargo test --test conformance_tests
```

After the run, two artifacts land in `target/conformance/`:

- `coverage.json` — machine-readable matrix for dashboards / CI gates.
- `coverage.md` — human-readable Markdown table operators paste into
  status pages.

Both files are written atomically (write to `.tmp`, rename) so a concurrent
`cat target/conformance/coverage.md` never observes a partial line.

## GA product contract

The machine-readable GA contract lives in
`tests/conformance/ga_contract.yaml`. It is the source of truth for the
semantic GA rows enforced by `tests/conformance/ga_scope.rs` and for the live
datapath assertion IDs that Kubernetes suites must eventually emit.

Every GA capability entry declares a stable capability ID, maturity, topology,
config protocol, semantic conformance rows, required live suite, required live
assertion IDs, platform profile, docs anchor, and owner.

`cargo test --test conformance_tests -- --test-threads=1` with
`FERRUM_CONFORMANCE_STRICT_GATE=1` fails when a GA semantic row is deleted,
renamed, filtered out, or tagged GA without a manifest entry. The emitted
`coverage.json` and `coverage.md` include the manifest-backed GA contract so
reviewers can compare the generated matrix to the declared product promise.

## Status values

The matrix tags each feature with one of three statuses:

- **`supported`** — Ferrum Edge implements the feature as documented;
  the test asserts the expected behavior. Most entries land here.
- **`deferred`** — A known gap. The test records the expected behavior;
  the `notes` column describes the tracking work (typically a follow-on
  PR or a documented runtime gap).
- **`out_of_scope`** — Explicit non-goal (e.g. Wasm filters,
  `EnvoyFilter`). Documented for completeness so operators stop asking.

There is no `bug` status. Tests that hit an unexpected failure must be
removed or fixed before they land — the suite is all-green in `main`.

## How to add a new Istio conformance test

1. Pick the right module under `tests/conformance/`. Add a new module if
   the surface doesn't fit (e.g. `istio_telemetry.rs` for the Telemetry
   CRD), then register it in `tests/conformance/mod.rs`.
2. Each test must call `register_feature!(category = ..., feature = ...,
   status = ..., notes = ...)` exactly once at the top of the test body.
   Use a distinct `feature` name per test — a single test covering two
   features would force operators to read the test source to learn which
   assertion proved which feature.
3. Drive translation through the public API (`translate_k8s_objects`,
   `prepare_gateway_config_for_mesh`, `translate_mesh_slice_to_snapshot`)
   so the conformance test exercises the same code path operators hit.
4. For matcher-style features, run the resulting plugin on a synthetic
   request and assert the visible outcome (route override, reject, etc.)
   rather than poking at the plugin internals.
5. Avoid any test that requires a real Kubernetes cluster, real network,
   or real timeout. The suite must be deterministic so CI gates can
   trust it.

To promote a feature into the GA contract, add or update the capability in
`tests/conformance/ga_contract.yaml`, tag the registering semantic row with
`Maturity::Ga`, and include the required live assertion IDs. Do not label a
feature GA from in-process coverage alone; required live IDs must correspond to
real Kubernetes datapath assertions.

The macro stamps `module_path!()` as the `test` column in the matrix; the
test function name surfaces via the standard cargo-test output. Operators
who want to investigate a specific feature can
`cargo test --test conformance_tests <feature_name_substring>`.

## Deferred entries

The current run records these `deferred` entries:

- `istio_destination_rule` —
  `trafficPolicy.connectionPool.http.{http1MaxPendingRequests, maxRetries,
  h2UpgradePolicy}` are projected and enforced at top-level /
  `portLevelSettings` (F5.1 — all three now `supported`); they remain deferred
  ONLY when set inside a `subsets[].trafficPolicy` (the subset apply path builds
  a `SubsetTrafficPolicy` that carries no `connectionPool.http`).

Previously deferred and now flipped to `supported`:

- `istio_virtual_service.authority.{exact,prefix,regex}` — first-class
  `mesh_route_dispatch` `StringMatch` predicate (T1-B.3 / PR #899). Regex
  patterns compile once at config-load time; `exact` / `prefix` operands
  match raw `Host` / `:authority` case-sensitively, including explicit
  request ports.
- `istio_virtual_service.ignoreUriCase: true` — first-class via
  escaped case-insensitive `listen_path` widening for exact/prefix URI
  matches + per-rule `ignore_uri_case` flag (T1-B.5 / PR #901). Regex URI
  matches keep their operator regex. Plugin re-evaluates exact/prefix with
  ASCII-only case folding; non-ASCII bytes compare byte-for-byte (matches
  Istio).

## Out-of-scope entries

- **Wasm filters** — Ferrum Edge runs native Rust plugins (`custom_plugins/`);
  Wasm filters are an explicit non-goal.
- **`EnvoyFilter`** — Envoy-specific extension API; not part of Ferrum's
  compatibility surface.
