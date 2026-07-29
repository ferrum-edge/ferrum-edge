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
  irrelevant PR passes). The `gate` job (`Gateway API Conformance`) is a
  branch-protection required check in its own right — `ci.yml` no longer runs
  a runner-holding mirror job for it. The workflow is **not** advisory.

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
| `HTTPRoute` weighted `backendRefs` | Yes | Multiple non-zero backends create a weighted upstream; a rule whose backendRefs are **all** `weight: 0` remains traffic-capturing and returns HTTP 500 through a synthesized fault-abort — see [backendRef port and zero-weight semantics](#backendref-port-and-zero-weight-semantics) |
| Cross-namespace `HTTPRoute.backendRefs` | Yes | Requires an exact `ReferenceGrant`; missing grants are rejected and unresolved |
| Cross-namespace `parentRefs` | Yes | Allowed only when the referenced Gateway listener permits the route namespace. `allowedRoutes.namespaces.selector` is parsed atomically with Kubernetes label-key/value and operator-cardinality validation; a malformed component invalidates the listener and attaches no routes. |
| Invalid backend references | Yes | Missing Services, unsupported backend target kinds, and unpermitted cross-namespace refs are reported as unresolved and materialize fail-closed HTTP 500 routes |
| Selectorless/headless Services | Yes | With pod discovery enabled, backends resolve ready EndpointSlice addresses directly; a named Service `targetPort` resolves against EndpointSlice port names, but the `backendRef.port` itself is numeric-only — see [backendRef port and zero-weight semantics](#backendref-port-and-zero-weight-semantics) |
| Backend failure | Yes | Traffic to unavailable generated backends must return an error response rather than falling through |
| Route update and deletion | Yes | Reconciliation regenerates live proxy/upstream/plugin config; deletion removes the route from live config |
| `GRPCRoute` | Not claimed by the `GATEWAY-HTTP` gate | Watched and translated — see [GRPCRoute predicate translation](#grpcroute-predicate-translation) — but not advertised as a passing upstream `GATEWAY-GRPC` profile until request traffic conformance is added |
| `TCPRoute` | Yes, via Ferrum black-box live checks (not upstream `GATEWAY-TCP`) | Lab installs the pinned `v1.5.1` experimental-channel CRD bundle (one coherent channel that includes `TCPRoute`). Live kind traffic proves parent/listener attachment, same-namespace and ReferenceGrant cross-namespace backend resolution, tagged TCP echo forwarding, empty/missing/unpermitted backend fail-closed behavior, parent status (`Accepted`/`ResolvedRefs`/`Programmed`), live backendRef updates, and deletion withdrawal. Upstream profile/features remain `GATEWAY-HTTP` / `Gateway,ReferenceGrant,HTTPRoute`; `GATEWAY-TCP` is **not** claimed on this pin (the profile/tests land in later Gateway API releases). |
| `TLSRoute` | Not claimed | Watched/translated for L4 experiments, but not advertised as a supported Gateway API conformance profile |
| `UDPRoute`, `BackendTLSPolicy`, `ListenerSet`, `BackendLBPolicy` | No | Not claimed as effective Gateway API conformance features |

## GRPCRoute predicate translation

`GRPCRoute.spec.rules[].matches[]` is translated on its own terms; a gRPC
predicate is never rewritten into an invented HTTP catch-all path, and it is
never dropped for being pathless.

| `matches[]` shape | Materialized as |
|---|---|
| `method.type: Exact` with `service` **and** `method` | Exact listen path `=/{service}/{method}` — the method predicate itself is fully represented by that listen path; the mandatory gRPC `content-type` gate still runs at request time |
| `method.type: Exact` with `service` only | Listen path prefix `/{service}/` — a gRPC `:path` always carries a trailing method segment, so this selects exactly that service |
| `service` written in fully-qualified `.pkg.Svc` form | The optional leading `.` is normalized away — a gRPC `:path` never carries it, so `.pkg.Svc` and `pkg.Svc` denote the same service and collapse onto the same route |
| `method.type: Exact` with `method` only | `/` listener plus a `mesh_route_dispatch` URI regex `/[^/]+/{method}` (the method literal is regex-escaped) |
| `method.type: RegularExpression` | **Not supported** — dropped fail closed (see below) |
| Header-only match (no `method`) | `/` listener plus the "any gRPC call" URI regex `/[^/]+/[^/]+` and the exact header predicates |
| Rule with `matches` omitted or empty | `/` listener plus the "any gRPC call" URI regex — the Gateway API defines this as every **gRPC** call on the route's hostnames, not every HTTP request |

`method.type: RegularExpression` is an implementation-specific Gateway API
extension that Ferrum does not implement. A gRPC `:path` is
`/{service}/{method}`, and an operator-supplied pattern can consume the `/`
delimiter through `.*`, a character class, or an encoded escape (`\x2F`,
`\u{2F}`) — wrapping the operand in a non-capturing group does not constrain it
to one path segment. Rather than emit a matcher that could silently widen a
route across service and method boundaries, the predicate is refused and the
match is dropped with a field-specific warning. Use `Exact` `service` /
`method` matches (including the service-only and method-only forms) instead.

**Every** emitted GRPCRoute match — including one whose predicate is carried
entirely by an exact `=/{service}/{method}` listen path or a `/{service}/`
prefix — additionally carries a `content-type` predicate. That gate is the
regex transcription of Ferrum's canonical **native**-gRPC content-type contract
(`proxy::backend_dispatch::is_native_grpc_content_type`): the
`application/grpc` essence followed by end-of-value, a `+` suffix, a `;`
parameter list, or optional whitespace leading to either, compared
case-insensitively. A GRPCRoute therefore only ever selects gRPC calls: neither
a pathless rule nor an exact gRPC path can capture ordinary HTTP traffic
sharing the same hostname and path.

`application/grpc-web` and `application/grpc-web-text` are **not** native gRPC
and are refused by the gate, exactly as the proxy's own dispatcher refuses
them — as are lookalikes such as `application/grpcfoo` and
`application/grpc-website`. gRPC-Web is served by configuring the trusted
`grpc_web` plugin, which verifies the request and rewrites it to native
`application/grpc` before backend dispatch; the route gate must not
independently bless the raw wire form.

A route-authored `content-type` header match replaces that gate (it is the more
specific operator intent), but it is validated against the same native contract,
so an operator header can only narrow the protocol boundary and never widen it;
a `content-type` predicate such as `text/plain`, `application/grpc-web`, or
`application/grpcfoo` drops the match fail closed. The generated
`mesh_route_dispatch` instance sets `reject_unmatched: true` unless another
**GRPCRoute** on the same listener contributes an unconditional match for the
same `(hostname, listen path)`.

Rule and match ordering is preserved: gRPC predicates sharing a listen path
collapse into one ordered dispatch-rule list (method-bearing before
header-count before route `creationTimestamp`, then namespace/name, rule
index, and match index), so fall-through between a specific rule and a later
broader rule behaves as written. Two GRPCRoutes only conflict when they claim
the *same* predicate on the same parent, hostname, and listen path; distinct
methods on the shared `/` listener are distinct routes, not a collision.

### HTTPRoute and GRPCRoute never merge

Gateway API v1.5.1 `GRPCRouteRule` states that "Merging MUST not be done between
GRPCRoutes and HTTPRoutes", and `GRPCRouteSpec` requires that when an HTTPRoute
and a GRPCRoute attach to the same listener with **any** intersecting hostname,
implementations accept exactly one of them.

Ferrum resolves that as a **whole-route** decision, before either object
materializes anything:

- The two routes are compared by oldest `metadata.creationTimestamp`, then
  `{namespace}/{name}` — the same deterministic tiebreaker as the same-kind
  path — and finally by `kind`, independent of the order objects are observed
  in. The `kind` tiebreak matters only here: `{namespace}/{name}` is unique
  within one kind, but an HTTPRoute and a GRPCRoute may share a name, and
  `metadata.creationTimestamp` has second granularity, so one `kubectl apply`
  of both ties on every Gateway API ordering field.
- Rule paths and match predicates are **not** consulted. An HTTPRoute catch-all
  and a GRPCRoute method predicate on the same host are a conflict even though
  their predicates are disjoint.
- The losing Route produces no proxy, no upstream, no plugin, and no
  materialized-parent record for the rejected `(parentRef, hostname)` claim, so
  it cannot route traffic. It is reported `Accepted=False` with
  `reason: Conflicted` and a message naming the winner, and the translator emits
  a matching warning.
- Resolution is per listener and per hostname intersection. The same GRPCRoute
  can still win on a hostname the HTTPRoute does not claim, or on a *separate*
  parentRef claim (for example a second `sectionName`-pinned reference) that
  reaches only a listener it wins. What it cannot do is keep one shared claim on
  a subset of the listeners that claim reaches — see the wildcard rule below.
- Rejection does not cascade: a route is only rejected when it overlaps an
  **accepted** route of the other kind, so a second HTTPRoute is unaffected by a
  GRPCRoute that already lost.

"The same listener" means the **resolved** listener, not the literal
`parentRefs[]` entry. A parentRef is a selector, so the two are not
interchangeable:

- A wildcard reference (no `sectionName`, no `port`) and a reference pinning that
  listener by `sectionName` or `port` attach to the same listener and therefore
  contend, even though their selector shapes differ.
- Two wildcard references on one Gateway that `allowedRoutes.kinds` sends to
  *different* listeners never share one, so neither is rejected.
- A wildcard reference that reaches several listeners is arbitrated on each of
  them independently, but it emits one shared conflict claim, which cannot
  express a partial withdrawal — and Ferrum's route representation is
  port-agnostic (see the known limitation below), so a claim kept for the
  listener it won would still route on the listener it lost. Such a claim is
  therefore **conservatively withdrawn whole on a loss on any listener it
  reaches**, and the reported winner is the accepted opposite-kind Route on the
  lowest-ordered listener it lost on. Availability on the non-conflicting
  listener does not take priority over not serving cross-kind traffic on the
  conflicting one.

Route status is still reported against the parentRef the operator wrote —
listener resolution is an internal arbitration detail and never rewrites the
`parentRef` echoed in `status.parents[]`.

Same-kind behavior is unchanged: two HTTPRoutes (or two GRPCRoutes) sharing a
`(hostname, listen path)` still collapse into one ordered dispatch-rule list,
and only claim-for-claim collisions are resolved as conflicts.

The prohibition is enforced where it applies — coexistence on one resolved
listener — and not as a blanket ban on the route-proxy collapse. Two Routes that
Gateway API requires be accepted *together* because they resolve to different
listeners share Ferrum's single port-agnostic `(hosts, listen path)` slot, so
they collapse into one ordered dispatch-rule list even across kinds. That is a
representation detail, not spec-forbidden rule merging: the two kinds'
predicates stay intact and disjoint inside that list, because every emitted
GRPCRoute rule carries the native-gRPC `content-type` gate and can therefore
only select gRPC calls, while everything else falls through to the HTTPRoute's
own rules and default backend. The alternative — one proxy each — is not a
choice the route table can express; it fails
`validate_unique_listen_paths` and aborts the whole config reload. This matters
in the ordinary "HTTP listener plus gRPC listener on one Gateway" topology,
where a pathless GRPCRoute predicate always lands on `/` and so does an
HTTPRoute `PathPrefix: /` rule.

**Known limitation.** Ferrum materializes Gateway API HTTP-family routes as
port-agnostic `(hosts, listen path)` proxies, so listeners of one Gateway are
not distinguishable in the route table. Two consequences follow:

- Two routes that legitimately survive on different listeners but claim the same
  `(hostname, listen path)` share one route-table slot rather than being served
  per listener port: their rules collapse into one ordered dispatch list, and a
  request that matches the other listener's route is answered on both listener
  ports. Give such routes distinct listen paths, distinct hostnames, or distinct
  Gateways when per-listener isolation is required.
- A single `(parentRef, hostname)` claim spanning several listeners cannot be
  restricted to the listeners it won, so a cross-kind loss on any one of them
  withdraws the claim from all of them (above). A GRPCRoute that must keep
  serving a listener an HTTPRoute also claims elsewhere needs a parentRef that
  reaches only that listener (`sectionName` or `port`), a non-intersecting
  hostname, or a separate Gateway.

### Fail-closed match shapes

Shapes Ferrum cannot represent exactly are **dropped fail closed** with a
field-specific translator warning (`GRPCRoute {ns}/{name}
rules[i].matches[j] dropped fail-closed: …`) rather than widened. The
`Exact` operand grammars are exactly the ones the v1.5.1 CRD enforces, so a
predicate the API server would have admitted is never rejected and a
hand-authored one that it would have rejected never reaches routing state:

- `method.type: RegularExpression`, and any `method.type` other than `Exact`.
- A `method` block with neither `service` nor `method`.
- An `Exact` `service` that is empty, longer than 1024 bytes (the CRD's
  `MaxLength=1024`; both grammars are ASCII-only, so bytes and characters
  coincide for any operand the API server could have admitted), or does not
  match `^\.?[a-z_][a-z_0-9]*(\.[a-z_][a-z_0-9]*)*$` (applied
  case-insensitively) — so a leading digit or hyphen, an empty dotted segment,
  a path separator, a percent escape, or whitespace is refused.
- An `Exact` `method` that is empty, longer than 1024 bytes, or does not
  match `^[A-Za-z_][A-Za-z_0-9]*$` — a single protobuf identifier, so a dot or
  hyphen is refused here even though `service` allows the dot.
- A `content-type` header match whose value is not a native gRPC media type — it
  would replace the protocol gate and widen the route onto non-gRPC traffic.
- `headers[].type: RegularExpression`, or a header match missing `name` or
  `value` — only `Exact` header matches are translated, matching the HTTPRoute
  translator.
- An **explicit** `method: null` or `headers: null`. An explicit null is
  malformed input, not an omission: reading it as absent would widen `method`
  into the any-gRPC-call predicate and `headers` into the headerless match.
  *Omitting* either field keeps its documented meaning — an omitted `method`
  matches any gRPC call on the route's hostnames, and omitted `headers` adds no
  header predicate.
- A **present but non-string** `method.service` or `method.method` (including an
  explicit null). Reading it as an omission would silently degrade an exact
  `=/{service}/{method}` listener into the far broader method-only or
  service-only shape.
- A match entry carrying **both** `method` and Ferrum's hand-authored
  `matches[].path` extension. `path` is not a GRPCRoute CRD field (the API
  server prunes it), and Ferrum's plan is a single listen path *or* a single URI
  predicate, so honoring either half alone would discard the other and widen the
  match. Use one or the other.

Refusal warnings never echo the operator-supplied operand or header value back,
since both are unbounded, attacker-influenceable input.

A rule whose every match is dropped materializes no route, so its parent status
is not reported as programmed.

## backendRef port and zero-weight semantics

These behaviors are exercised by the black-box lab (invalid and weighted refs)
and specified field-by-field in [`docs/configuration.md`](configuration.md)
(Kubernetes Mesh Integration — the authoritative field-level reference). They
are summarized here because they are common conformance questions. These are
single-cluster Gateway API behaviors, not cross-cluster or UDP mesh surfaces.

- **Invalid / unresolved backendRef** (missing Service, unsupported backend
  kind, or an unpermitted cross-namespace ref) materializes a fail-closed route
  that returns **HTTP 500**, matching the Gateway API expectation. The
  black-box lab asserts the `/invalid` route returns `500`.
- **Zero-weight-only rule** (every `backendRef` in a matched rule has
  `weight: 0`) is *not* dropped. Ferrum keeps the route materialized and applies
  the same synthesized 100% fault-abort used for wholly invalid/unresolved
  backendRefs, so matching traffic returns **HTTP 500** instead of falling
  through to a broader later route. The translator test
  (`http_route_keeps_all_zero_weight_rule_as_500_fault`) pins the route and
  fault shape; the black-box lab asserts `/zero-weight` returns `500` even with
  a later `/zero` backend route.
- **backendRef port is numeric-only in the upstream CRD.** Gateway API v1.5
  defines `HTTPBackendRef.port` as `PortNumber`: for a Kubernetes Service it is
  the numeric Service port, not the target port. There is therefore no named
  `backendRef.port` field for Ferrum to implement. Once that numeric port
  selects `Service.spec.ports[]`, its `targetPort` may be a named pod port;
  Ferrum resolves it against `EndpointSlice.ports[].name`. The translator test
  (`http_route_selectorless_service_resolves_named_target_port`) covers this
  Gateway API path. Istio `VirtualService` separately supports
  `destination.port.name`, resolved against `Service.spec.ports[].name`.

## CI Evidence

The standalone `gateway-api-conformance.yml` workflow is the single owner that deploys the lab on PRs, and its `gate` job is the authoritative conformance check, required directly via branch protection (there is no mirror job in `ci.yml`). The lab consists of:

- Ferrum control plane/controller with Gateway API watches enabled.
- A routable Ferrum data-plane deployment and NodePort Service mapped to host ports 80 and 443 (HTTP/HTTPS) plus dedicated TCPRoute stream ports `9001`–`9004` in kind.
- HTTP echo backend namespaces plus tagged TCP echo fixtures for live `TCPRoute` checks.
- `GatewayClass`, `Gateway`, `HTTPRoute`, `GRPCRoute`, `TCPRoute`, and `ReferenceGrant` resources for direct black-box checks.
- The upstream Gateway API conformance suite pinned by `GATEWAY_API_VERSION`, defaulting to `v1.5.1`, running the complete `GATEWAY-HTTP` profile with explicit supported features `Gateway,ReferenceGrant,HTTPRoute` (unchanged; TCPRoute is gated by Ferrum black-box evidence, not by advertising an upstream `GATEWAY-TCP` profile on this pin).

Direct black-box checks cover hostname, path, method, headers, weighted backend selection, zero-weight-only HTTP 500 behavior, cross-namespace references, invalid references, backend failure, TLS, route updates, and route deletion for HTTP, plus TCPRoute parent/listener attachment, ReferenceGrant backend resolution, tagged echo traffic, fail-closed empty/missing/unpermitted backends, status, update, and deletion. Diagnostics and the upstream conformance report are uploaded from `conformance-results/` as retained CI artifacts.

Lab bootstrap uses `scripts/gateway_api_conformance_lab_setup.sh` (kind ports, experimental CRDs, TCP listener Service ports). HTTP/GRPC upstream and black-box phases stay in `scripts/gateway_api_data_plane_conformance.sh`; TCPRoute black-box and supplemental diagnostics run via `scripts/gateway_api_tcproute_conformance.sh` so the Trusted Cross Build Policy frozen `gateway_api_data_plane_conformance.sh` surface on `main` stays untouched.

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

GatewayClass and Gateway status updates use Kubernetes server-side apply with
the stable field manager `ferrum.io/gateway-controller`. Their structural
condition and listener lists are keyed list-maps, so the minimal apply document
can own Ferrum's entries without copying another manager's fields. Ferrum sets
`force=true` to reclaim the status fields it continuously reconciles after
upgrades or legacy merge-patch writes.

Route `status.parents` is an atomic list in the upstream Gateway API CRDs, so a
partial server-side apply would still replace the entire list and could remove
another controller's parent entries. Ferrum instead follows the upstream
read-modify-write requirement: it reads the freshest status, preserves every
non-Ferrum parent, replaces only Ferrum-owned parents, and includes that read's
`metadata.resourceVersion` in the merge patch. A `409 Conflict` triggers a
refetch, re-merge, and jittered retry (up to five attempts); exhaustion leaves
the resource for the next reconcile rather than writing stale status.

`Programmed=True` on a Gateway is additionally gated on the serving data-plane
Service having a ready EndpointSlice endpoint when
`FERRUM_GATEWAY_API_DATA_PLANE_SERVICE_NAMESPACE`/`_NAME` are set; otherwise it
reflects translation/materialization only. Route programming uses the typed
route-to-parent materialization records emitted alongside proxy generation; it
does not reconstruct source routes from proxy ID strings.

A malformed `allowedRoutes.namespaces.selector` sets the affected listener's
`Accepted=False` and `Programmed=False` conditions with reason `Invalid`.
The condition message contains only the stable selector field path and
validation class; label keys, label values, and unknown operator text are not
echoed. `attachedRoutes` is `0`, and reconciliation withdraws any attachment
previously materialized by an older valid selector. Valid sibling listeners
continue to reconcile independently.

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
`scripts/gateway_api_data_plane_conformance.sh diagnostics` (plus
`scripts/gateway_api_tcproute_conformance.sh diagnostics` for TCPRoute log
snapshots and the extended `gateway-api-resources.yaml`):

| File | What it is |
| --- | --- |
| `gateway-api-conformance-test.json` | Streaming `go test -json` events for every upstream conformance test. |
| `gateway-api-conformance-report.yaml` | Upstream `conformance.gateway.networking.k8s.io` report; `profiles[].coreTests` has pass/fail per test. |
| `gateway-api-blackbox.md` | Results of the direct black-box traffic checks (HTTP host/method/header/modifier/cross-namespace/redirect/weighted/invalid-500/zero-weight-500/no-endpoints/update/delete/TLS, plus TCPRoute attachment/status/echo/ReferenceGrant/fail-closed/update/delete). |
| `gateway-api-resources.yaml` | `kubectl get gatewayclasses,gateways,httproutes,grpcroutes,tcproutes,referencegrants -A -o yaml` snapshot. |
| `kubernetes-workloads.txt`, `namespaces.txt`, `ferrum-*-deployment.txt`, `ferrum-pods.txt`, `ferrum-events.txt` | Cluster/workload diagnostics. |
| `ferrum-control-plane.log`, `ferrum-control-plane-previous.log`, `ferrum-data-plane.log`, `blackbox-*.log` | Container logs. |
| `CONFORMANCE.md` (run-local) | Per-run metadata (version, profile, features, data-plane Service, artifact list). Generated by the script — distinct from the repo-root [`CONFORMANCE.md`](../CONFORMANCE.md). |

## In-process Istio + xDS suite

The second compatibility surface — Istio `networking.istio.io` /
`security.istio.io` CRDs plus the xDS type URLs Ferrum subscribes to — is
covered by the in-process `tests/conformance/` suite, documented under
[Istio + xDS Conformance Suite](../CONFORMANCE.md#istio--xds-conformance-suite)
in the repo-root conformance index.
