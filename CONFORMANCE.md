# Conformance

Ferrum's conformance story spans two surfaces, each with its own owner doc:

1. **Upstream Gateway API conformance** — the `gateway.networking.k8s.io`
   `GatewayClass` / `Gateway` / `HTTPRoute` / `GRPCRoute` surface (plus live
   black-box `TCPRoute` / `TLSRoute`, and `UDPRoute`), validated by the
   standalone **`Gateway API Conformance`** GitHub Actions workflow
   (`.github/workflows/gateway-api-conformance.yml`) against a real
   `kind` data plane for HTTP/TCP/TLS. `UDPRoute` is gated inside the required
   `Tests` aggregate instead: CI Unit Tests for translation/status/lifecycle,
   plus a live UDP **data-path** integration suite that runs a translated
   `UDPRoute` through the real `start_udp_listener` runtime.
2. **Istio + xDS compatibility** — the in-process suite under
   `tests/conformance/`, documented in
   [Istio + xDS Conformance Suite](#istio--xds-conformance-suite) below.

## Gateway API (upstream `gateway.networking.k8s.io`)

**Canonical reference: [`docs/gateway_api_conformance.md`](docs/gateway_api_conformance.md).**
That document is the single source of truth for the Gateway API workflow's
**gating status, claimed profiles/features, listener-status emission,
data-plane coverage, and uploaded artifacts.** This page only summarizes and
links — update the canonical doc, not this summary, when the workflow
changes.

Summary of current behavior (see the canonical doc for detail and code
citations):

- **Gating.** The workflow **gates** PRs, the merge queue, and `main` pushes. Its `gate` job
  (`Gateway API Conformance`) fails on any upstream-conformance or black-box
  failure and is a branch-protection required check directly — there is no
  mirror job in `ci.yml`. It is not advisory.
- **Triggers.** `pull_request`, `merge_group`, `push` to `main`, weekly `schedule`
  (Mondays 07:00 UTC), and manual `workflow_dispatch`. A path-filter `changes`
  job skips the heavy lab when no routing / translation / chart / image / proto
  / CI surface changed.
- **Profile & features.** Gateway API `v1.5.1`, profiles
  `GATEWAY-HTTP,GATEWAY-GRPC`, supported features
  `Gateway,ReferenceGrant,HTTPRoute,GRPCRoute` plus the Extended filter features
  `HTTPRouteResponseHeaderModification`, `HTTPRoutePathRewrite` and
  `HTTPRouteHostRewrite` and the rule-timeout features `HTTPRouteRequestTimeout`
  and `HTTPRouteBackendTimeout` (two known deviations, below), GatewayClass
  `ferrum`, controller `ferrum.io/gateway-controller`. Live `TCPRoute` and
  `TLSRoute` data-plane behavior is release-gated by Ferrum black-box checks in
  the same workflow. `UDPRoute` is release-gated by the required `Tests` aggregate
  rather than by a black-box step in this workflow:
  translation/status/update/delete by CI Unit Tests
  (`tests/unit/gateway_core/k8s_udproute_translation_tests.rs`), and the
  **live UDP data path** by CI Integration Tests
  (`tests/integration/gateway_api_udproute_datapath_tests.rs`), which serve a
  translated `UDPRoute` on the real UDP runtime and assert a datagram reaches
  the backend the route named. No upstream `GATEWAY-TCP` / `GATEWAY-TLS` /
  `GATEWAY-UDP` profile is advertised on this pin.
- **Data plane.** The lab deploys a routable Ferrum **data plane** (NodePort
  mapped to host ports 80/443 plus TCPRoute and TLSRoute stream ports) plus
  HTTP/TCP/TLS echo backends, then runs the upstream suite **and** direct
  black-box traffic checks — it is not a control-plane-only status run.
- **Status.** GatewayClass, Gateway top-level, **per-listener**
  (`status.listeners[]` conditions / `attachedRoutes` / `supportedKinds`), and
  HTTPRoute/GRPCRoute/TCPRoute/TLSRoute/UDPRoute parent status are all
  emitted. The canonical doc records the reason-string divergences from the
  upstream constants table.
- **Artifacts.** A `gateway-api-conformance-<version>` bundle
  (`conformance-results/`, 90-day retention). The **run-local `CONFORMANCE.md`**
  inside that bundle is generated per run by
  `scripts/gateway_api_data_plane_conformance.sh` (with TCPRoute, TLSRoute, and
  ListenerSet details appended by `scripts/gateway_api_tcproute_conformance.sh`,
  `scripts/gateway_api_tlsroute_conformance.sh`, and
  `scripts/gateway_api_listenerset_conformance.sh`) and is a different file from
  this repo-root page.

## Gateway API rule feature admission

Summary only; the canonical rules, status-reason table, and known deviations
are in [Rule-filter admission](docs/gateway_api_conformance.md#rule-filter-admission),
[Rule timeouts](docs/gateway_api_conformance.md#rule-timeouts), and
[Rule retry](docs/gateway_api_conformance.md#rule-retry).

**Supported rule features.** HTTPRoute and GRPCRoute support rule-level
`RequestHeaderModifier` and `ResponseHeaderModifier`. HTTPRoute also supports
`RequestRedirect`, `URLRewrite` (both HTTPRoute-only upstream, so a GRPCRoute
asking for either is refused), rule `timeouts`, and rule `retry`. The admitted
rule fields are `name`, `matches`, `backendRefs`, `filters`, and
`sessionPersistence`, plus `timeouts` and `retry` on HTTPRoute. An HTTPRoute
rule with no `backendRefs` and no `RequestRedirect` whose only filters are
header modifiers and/or `URLRewrite` answers HTTP 500, as upstream requires for
a rule that forwards nowhere.

**Refusals.** Unsupported shapes are refused before any route configuration is
emitted, never partially honored; they report `Programmed=False` while
independently valid routes stay available. The status reason follows what is
wrong, not which CRD mechanism forbids it:

- `IncompatibleFilters` — the filter set cannot be honored as declared:
  `RequestMirror`, `ExtensionRef`, `CORS`, `ExternalAuth`, and backend-reference
  filters (not implemented); `URLRewrite` + `RequestRedirect` in one rule; a
  repeated `RequestHeaderModifier`, `ResponseHeaderModifier`, `RequestRedirect`,
  or `URLRewrite`; or an unknown field inside a supported filter.
- `Invalid` — a bad value inside one filter: malformed header names/values,
  rewrite hostnames or replacement paths, or `ReplacePrefixMatch` with a
  non-`PathPrefix` match in the rule.
- `UnsupportedValue` — a CRD-valid value Ferrum declines: unknown filter types,
  `timeouts`/`retry` on a GRPCRoute (upstream does not define them), a
  `ResponseHeaderModifier` naming a hop-by-hop/framing field or setting, adding,
  or removing `grpc-status`, `grpc-message`, or `grpc-status-details-bin`.

**Rule `timeouts` (HTTPRoute, standard channel).** Validated exactly as the
pinned CRD does (GEP-2257 durations; a non-zero `request` bounds
`backendRequest`); `0s` disables either bound. `backendRequest` bounds each
backend attempt from its handoff until the full response is received, with a
fresh budget per retry. `request` is one absolute budget for the whole
transaction: every attempt, retry backoff, and the streaming response body.
Both stay on the rule's own dispatch entry, so sibling and merged rules keep
the proxy defaults. Upgraded WebSocket / CONNECT-UDP tunnels are not bounded by
`request`. A `request` expiry is charged to a backend's health only when that
backend held the request.

**Known deviations in the declared rule-timeout features:**

- **`HTTPRouteBackendTimeout`:** HTTP/1.1, HTTP/2 and native HTTP/3 enforce the
  upstream definition for non-gRPC requests. A gRPC or gRPC-Web call folds the
  budget into its RPC deadline when the rule is selected rather than at the
  handoff (stricter: gateway-side time before the handoff counts against the
  first attempt), and a gRPC budget expiry is not retried, since gRPC calls are
  retried only after connection failures. Both are intentional (decided in
  #5734). The upstream test delays only the response head, which every
  frontend bounds.
- **`HTTPRouteRequestTimeout`:** no known deviation. HTTP/3 stays advertised
  (`Alt-Svc`) on a listener port that serves a timed rule.

**Rule `retry` (HTTPRoute, experimental channel).** Upstream `v1.5.1` defines no
retry conformance feature or test, so none is declared; behavior is pinned by
Ferrum's own data-plane regressions. `attempts` counts retries after the
initial attempt (`0` disables retry),
`codes` are the retried statuses (400–599), and `backoff` is a fixed minimum
wait. A negative `attempts`, one above 100, or a `backoff` above `5m` is
`UnsupportedValue`. A listed status is retried only for
`GET`, `HEAD`, `OPTIONS`, `PUT`, and `DELETE`; a failure before any byte reached
the backend is retried for every method; a response whose head reached the
client is never replayed. Every attempt and backoff spends the rule's
`timeouts.request` budget.

**Known deviation in rule `retry`:** upstream says implementations SHOULD retry
connection errors whenever `retry` is configured. Ferrum retries a failure that
happened after the request reached the backend only when the resulting gateway
status (`502` / `504`) is listed in `codes`, and only for the replay-safe
methods, so a request the backend may already have processed is never replayed.

**Response-trailer cost of `ResponseHeaderModifier`.** The requests a filtered
rule matches have their non-reserved backend trailers dropped. The drop is
per request: a merged sibling rule or route without a response-header filter
keeps its trailers. For native gRPC the terminal `grpc-status` /
`grpc-message` / `grpc-status-details-bin`, the message, and streaming are
preserved; other application trailers on the filtered rule are not.
`ResponseHeaderModifier` never modifies trailers.

**Evidence.** The upstream `HTTPRouteResponseHeaderModifier`,
`HTTPRouteRewritePath`, `HTTPRouteRewriteHost`, `HTTPRouteTimeoutRequest`, and
`HTTPRouteTimeoutBackendRequest` tests run and pass in the hosted lab. Ferrum's
own regressions in `tests/integration/k8s_controller_gateway_status_tests.rs`
include:

- admission: `unsupported_http_and_grpc_route_features_are_refused_before_materialization`
  (translator/status agreement for both route kinds, future fields, and a
  supported `RequestHeaderModifier` control) and
  `supported_gateway_request_headers_reach_backend_beside_rejected_route`;
- filters: `gateway_response_header_modifier_reaches_the_client_through_the_data_plane`,
  `gateway_url_rewrite_reaches_the_backend_through_the_data_plane`,
  `grpc_route_response_header_modifier_reaches_the_client_and_preserves_status`,
  `merged_grpc_route_sibling_without_response_header_modifier_keeps_trailers`,
  `merged_http_route_sibling_without_response_header_modifier_keeps_trailers`,
  and `removing_a_rule_filter_withdraws_its_generated_resources`;
- timeouts and retry: the regressions listed under
  [Rule timeouts](docs/gateway_api_conformance.md#rule-timeouts) and
  [Rule retry](docs/gateway_api_conformance.md#rule-retry).

The pinned [HTTPRoute v1.5.1 schema](https://github.com/kubernetes-sigs/gateway-api/blob/v1.5.1/apis/v1/httproute_types.go)
marks response-header modification and `URLRewrite` as Extended; the
[GRPCRoute filter-type contract](https://github.com/kubernetes-sigs/gateway-api/blob/v1.5.1/apis/v1/grpcroute_types.go)
lists response-header modification as Core and has no `URLRewrite`. The
remaining refusals above are conformance gaps; refusing them visibly does not
establish full conformance.

# Istio + xDS Conformance Suite

Ferrum ships an in-process conformance test suite at `tests/conformance/`
that exercises the second compatibility surface — Istio `networking.istio.io` /
`security.istio.io` CRDs plus the xDS type URLs Ferrum subscribes to — and
emits an auto-generated compatibility matrix operators can use to decide "is
this Istio config supported by Ferrum Edge?".

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
- **`istio_request_authentication`** — `jwtRules[]` translation (issuer,
  inline `jwks` vs `jwksUri`, audiences, header/param extraction,
  `forwardOriginalToken`, scope resolution).
- **`istio_service_entry_egress`** — `location: MESH_EXTERNAL` vs
  `MESH_INTERNAL`, HTTP-family + stream-family egress materialization
  (T5-A, PR #907), `outboundTrafficPolicy: REGISTRY_ONLY` injection
  (T5-B, PR #893), workload-scoped `Sidecar.outboundTrafficPolicy`
  override in both directions plus its fail-closed unsupported variants
  (issue #3262), hostname normalization.
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
- **`mesh_config_transport`**, **`mesh_spiffe_identity`**,
  **`mesh_multicluster_federation`** — hermetic semantics for the native
  `MeshSubscribe` config transport, SPIRE-backed identity decisions, and the
  config-plane half of multicluster federation (GA contract rows).
- **`stock_xds_interop`** — what a stock Envoy / Istio control plane can drive
  under `FERRUM_MESH_CONFIG_PROTOCOL=stock_xds`, and its declared residuals.

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

This section summarizes the in-process suite's `deferred` rows. The
**authoritative** matrix is the generated artifact from
`cargo test --test conformance_tests` → `target/conformance/coverage.md`
(and `coverage.json`); when this page and the generated file disagree, trust
the generated output from the latest green `main` run.

The current run records these `deferred` entries:

- `istio_destination_rule` —
  `trafficPolicy.connectionPool.http.maxRequestsPerConnection` is parsed and
  validated but not enforced (close-after-N backend requests unsupported) at
  any scope.
- `istio_virtual_service` — three fail-closed `http[].corsPolicy` shapes are
  left unprojected and reported in `status.deferred_fields`: an uncompilable,
  over-complex, or over-budget origin matcher; `allowCredentials` with an
  opaque `null` or effectively universal origin matcher; and a malformed
  `StringMatch` origin matcher.

Previously deferred and now `supported`:

- `istio_destination_rule` —
  `subsets[].trafficPolicy.connectionPool.http.{idleTimeout,http2MaxRequests}`
  at subset scope, alongside `h2UpgradePolicy`, `maxRetries`, and
  `http1MaxPendingRequests` (issue #3735). Field-level precedence is
  `portLevelSettings` > selected subset > top-level; `http2MaxRequests` is the
  destination-wide active-request breaker, keyed by the selected subset
  (issue #3775).

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
- **AuthorizationPolicy `when: experimental.envoy.filters.<filter>[<key>]`** —
  accepted so the policy still installs, but permanently unsourceable (no Envoy
  filter chain): DENY ignores the condition and still matches; ALLOW/AUDIT never
  match.
- **Stock xDS profile residuals** — the surfaces a stock control plane cannot
  drive (see `stock_xds_interop` above and
  [docs/mesh_supported_matrix.md](docs/mesh_supported_matrix.md)).
