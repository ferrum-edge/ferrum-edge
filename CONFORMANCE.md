# Gateway API Conformance

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
links so the two cannot drift again — update the canonical doc, not this
summary, when the workflow changes.

Summary of current behavior (see the canonical doc for detail and code
citations):

- **Gating.** The workflow **gates** PRs and `main` pushes. Its `gate` job
  (`Gateway API Conformance`) fails on any upstream-conformance or black-box
  failure and is a branch-protection required check directly — there is no
  mirror job in `ci.yml`. It is not advisory.
- **Triggers.** `pull_request`, `push` to `main`, weekly `schedule`
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
  `scripts/gateway_api_data_plane_conformance.sh` (with TCPRoute/TLSRoute ports
  and resources appended by `scripts/gateway_api_tcproute_conformance.sh` and
  `scripts/gateway_api_tlsroute_conformance.sh`) and is a different file from
  this repo-root page.

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

## Gateway API rule feature admission

HTTPRoute and GRPCRoute support rule-level `RequestHeaderModifier` and
`ResponseHeaderModifier`; HTTPRoute also supports `RequestRedirect` and
`URLRewrite` (both HTTPRoute-only upstream — a GRPCRoute asking for either is
still refused) and rule-level `timeouts` (below). RequestMirror, ExtensionRef,
CORS, ExternalAuth and backend-reference filters remain deferred. Translation
rejects a route containing these unimplemented filter actions with
`Accepted=False` / `IncompatibleFilters`; it does not emit partially interpreted
rules. Unknown filter types and unimplemented rule fields — `retry` on either
kind, and `timeouts` on a GRPCRoute, which upstream does not define — report
`UnsupportedValue`. Both cases report `Programmed=False`, while independently
valid routes remain available.

**Rule `timeouts` (HTTPRoute).** `timeouts.request` and
`timeouts.backendRequest` are validated exactly as the pinned standard-channel
CRD does: each must match the GEP-2257 duration grammar, and a non-zero
`request` must not be shorter than `backendRequest` (the CRD's CEL rule).
Violations, a non-string value and a non-object `timeouts` are `Invalid`; an
undefined `timeouts` sub-field is `UnsupportedValue`. `0s` disables either
bound. `backendRequest` bounds one backend attempt (its wait for response
headers and the idle gap between response frames) and answers the ordinary
backend-timeout `504`. `request` is one absolute budget, anchored at request
receipt, covering every attempt, retry backoff and the streaming response body:
before the response head a non-gRPC request gets a gateway `504`
(`{"error":"Request timeout"}`), a body still streaming at the deadline is
reset (HTTP/2) or its connection closed (HTTP/1.1), and a gRPC request folds the
budget into its RPC deadline and ends with `DEADLINE_EXCEEDED`. Both values stay
on the rule's own dispatch entry, so sibling and merged rules keep the proxy
defaults. A `request` expiry is charged to a backend's health (circuit
breaker, passive health / outlier detection, latency samples) only when that
backend held the request: expiry while the gateway is still collecting a
buffered client upload, running request-body hooks, resolving DNS or taking
admission, in retry backoff, or after the response head is health-neutral. A
body cut by `request` keeps a backend `Content-Length` advertised.

**Known deviations in the declared rule-timeout features:**

- **`HTTPRouteBackendTimeout`:** upstream v1.5.1 defines `backendRequest` as the
  time from when a request starts being sent to the backend until its full
  response is received, per attempt. Ferrum bounds each attempt's wait for the
  response head and every idle gap between response frames, not the attempt's
  total duration, so a backend trickling its body inside the idle gap is not cut
  per attempt; only `request` cuts it, and a rule without a non-zero `request`
  has no total bound. The upstream test delays only the response head.
- **`HTTPRouteRequestTimeout` over HTTP/3:** native HTTP/3 cannot yet enforce
  `request` on a non-gRPC request, so such a request is refused with `503`
  before any dial rather than served without its deadline. Because browsers
  cache `Alt-Svc` origin-wide and do not fall back to TCP on an HTTP error, the
  H1/H2 frontends withhold `Alt-Svc` on every listener port that serves such a
  rule (every port for a port-agnostic route), so the gateway never steers a
  client onto the refusal; a client that reaches HTTP/3 another way still gets
  the `503`. HTTP/1.1 and HTTP/2 enforce `request` fully.

Upgraded WebSocket / CONNECT-UDP tunnels are not bounded by `request`.

Filter shapes are refused rather than partially honored, and the status reason
follows what is wrong rather than which CRD mechanism forbids it:
`IncompatibleFilters` when the rule's filter set cannot be honored as declared
(conflicting filters, a filter type the kind does not carry, an unimplemented
filter type or field), `Invalid` for a bad value inside one filter, and
`UnsupportedValue` for a CRD-valid value Ferrum declines. So `URLRewrite` and
`RequestRedirect` in one rule are `IncompatibleFilters` (a redirect answers the
request itself, so the rewrite could never fire — upstream's own example of the
reason), and the four upstream at-most-once filter types —
`RequestHeaderModifier`, `ResponseHeaderModifier`, `RequestRedirect`,
`URLRewrite` — are refused when repeated in one rule. `URLRewrite`
`path.type: ReplacePrefixMatch` requires every match in the rule to use a
`PathPrefix` path match; anything else is `Invalid`, as is a `URLRewrite.path`
carrying the modifier field of the type it did not select. Upstream's CEL rule
is stricter (exactly one `PathPrefix` match); Ferrum also accepts several
`PathPrefix` matches and a match-less rule (the implicit `PathPrefix: /`), each
rebased against its own prefix. A `PathPrefix` match with no `value`, or a match
with no or a null `path`, rebases against `/`, matching upstream's default and
Ferrum's routing. A `ResponseHeaderModifier` naming a protocol-managed response
field (hop-by-hop or framing) is `UnsupportedValue`: Ferrum strips those from
backend responses by design and a route filter may not put one back. So is a
response-side `set` / `add` / `remove` of `grpc-status`, `grpc-message` or
`grpc-status-details-bin` on either kind, because a Trailers-Only gRPC error
carries its status in the headers the filter edits. Malformed header
names/values and malformed rewrite hostnames or replacement paths are `Invalid`.
An HTTPRoute rule with no `backendRefs` and no `RequestRedirect` whose only
filters are header modifiers and/or `URLRewrite` answers HTTP 500, as upstream
requires for a rule that forwards nowhere.

**Response-trailer cost of `ResponseHeaderModifier`.** A route override can name
any field at request time, so the requests a filtered rule matches have their
non-reserved backend trailers dropped by the gateway's response-trailer
governance boundary. The generated `response_transformer` consumer carries no
rules of its own and declares a request-conditional policy, so the drop applies
only when the matched dispatch rule published a response transform. Same-kind
routes that share a hostname, listener and path merge onto one proxy and one
consumer; a merged sibling rule or route that declares no response-header filter
keeps its trailers. The gRPC terminal fields (`grpc-status`, `grpc-message`,
`grpc-status-details-bin`), the response message and streaming are preserved;
application trailers on the filtered rule are not. The filter does not modify
trailers in either case — `ResponseHeaderModifier` governs response headers
only, which for a native gRPC call is the initial metadata.

The field inventory admits rule name, matches, backendRefs, filters and
sessionPersistence, plus `timeouts` on HTTPRoute, each subject to its existing
validation. Empty backend
filter lists have no action and remain accepted. Extra fields on a supported
filter or its payload are refused. The integration regression
`unsupported_http_and_grpc_route_features_are_refused_before_materialization`
checks translator/status agreement for both route kinds, all six reported gaps,
future fields, and a supported RequestHeaderModifier control (issue #4816).
`supported_gateway_request_headers_reach_backend_beside_rejected_route` also
drives the translated HTTPRoute through the gateway to a real backend and
checks header set/add/remove plus no traffic for the refused sibling. Five more
data-plane regressions in the same file cover the newly supported filters:
`gateway_response_header_modifier_reaches_the_client_through_the_data_plane`
(client-observed set/add/remove, sibling-rule isolation, and composition with an
operator's global `response_transformer`),
`gateway_url_rewrite_reaches_the_backend_through_the_data_plane`
(backend-observed `ReplacePrefixMatch` path plus preserved query,
`ReplaceFullPath`, hostname rewrite, and sibling-rule isolation),
`grpc_route_response_header_modifier_reaches_the_client_and_preserves_status`
(gRPC response metadata, message, terminal status, and the trailer cost above).
`merged_grpc_route_sibling_without_response_header_modifier_keeps_trailers` and
`merged_http_route_sibling_without_response_header_modifier_keeps_trailers`
first prove two routes merged onto one proxy and one consumer, then show the
filtered rule pays the trailer cost while the merged sibling keeps its
application trailers. The response-header test also asserts that `add` appends
to a header the backend already sent and that a filter-only rule with no
`backendRefs` answers `500`.
The translator-level `removing_a_rule_filter_withdraws_its_generated_resources`
checks that dropping a filter emits no rewrite, response transform, or consumer
plugin; the live reconciler replaces those generated ids on every compose
because `istio-vs-resp-xform-` is a managed plugin-id prefix. The upstream
`HTTPRouteResponseHeaderModifier`, `HTTPRouteRewritePath` and
`HTTPRouteRewriteHost` conformance tests run and pass in the hosted lab. The
upstream `HTTPRouteTimeoutRequest` and `HTTPRouteTimeoutBackendRequest` tests
now run too (their features are declared). Data-plane regressions cover rule
timeouts:
`gateway_route_timeouts_reach_the_data_plane` (pre-head `504`, mid-body cut,
`backendRequest` inside a larger `request` budget, `0s`, sibling isolation),
`gateway_route_request_timeout_spans_retry_attempts_and_backoff` (one budget
across attempts and backoff under an operator-configured proxy retry),
`gateway_route_request_timeout_ends_grpc_calls_with_deadline_exceeded`,
`removing_rule_timeouts_withdraws_the_deadline`, and three backend-health
attribution regressions through a live circuit breaker (a stalled client upload
and a mid-body cut are not charged; a backend stalling its response head is).
Default
HTTPRoute matches use the same internal predicate conversion as explicit
matches, so supported actions do not emit an invalid raw Gateway API path field.
The pinned [HTTPRoute v1.5.1 schema](https://github.com/kubernetes-sigs/gateway-api/blob/v1.5.1/apis/v1/httproute_types.go)
marks response-header modification and `URLRewrite` as Extended. The
[GRPCRoute filter-type contract](https://github.com/kubernetes-sigs/gateway-api/blob/v1.5.1/apis/v1/grpcroute_types.go)
lists response-header modification as Core and carries no `URLRewrite` variant.
Both are now implemented for the kinds upstream defines them on; the remaining
refusals above are still recorded as conformance gaps, and refusing them visibly
does not establish full conformance.

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
- `istio_destination_rule` —
  `subsets[].trafficPolicy.connectionPool.http.{idleTimeout,http2MaxRequests}`
  are now `supported` at subset scope alongside `h2UpgradePolicy`,
  `maxRetries`, and `http1MaxPendingRequests` (issue #3735): projected into
  `ResolvedSubsetTrafficPolicy`, overlaid onto the selected proxy's inherited
  fallback with field-level precedence `portLevelSettings` > selected subset >
  top-level. Direct-H2 / native-gRPC pool keys include the effective stream cap;
  Reqwest's H2 path still lacks an `http2MaxRequests` builder knob
  (documented transport caveat).

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
