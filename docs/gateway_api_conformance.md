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

- **Triggers:** `pull_request`, `merge_group` (merge-queue synthesized SHA),
  `push` to `main`, a weekly `schedule`
  (Mondays 07:00 UTC), and manual `workflow_dispatch` (whose inputs are
  `gateway_api_version`, `conformance_profile`, `supported_features`, and
  `skip_tests`). A lightweight `changes` job (path filter via
  `.github/scripts/live_suite_path_filter.py --suite gateway-api`) runs first
  and skips the ~90-minute lab unless the PR or merge-group change set touches
  routing, Kubernetes
  translation/status, CP/DP sync, data-plane startup, plugins, charts, the
  runtime image, proto, the conformance script, dependencies, or related CI.
  On `merge_group`, the filter diffs `merge_group.base_sha...HEAD` and fails
  closed if that base SHA is missing. Both pull-request and merge-group changed-
  file lists use `git diff --name-only --no-renames` so a rename's source and
  destination are both classified and a move into an irrelevant path cannot
  skip the lab.
- **Gating:** the workflow's `gate` job fails the check when change detection,
  the upstream suite, or the black-box checks fail (a lab skipped on an
  irrelevant PR passes). The `gate` job (`Gateway API Conformance`) is a
  branch-protection required check in its own right — `ci.yml` no longer runs
  a runner-holding mirror job for it. The workflow is **not** advisory.

## Default run parameters

| Parameter | Value |
|---|---|
| Gateway API version | `v1.5.1` |
| Conformance profile | `GATEWAY-HTTP,GATEWAY-GRPC` |
| Supported features | `Gateway,ReferenceGrant,HTTPRoute,GRPCRoute` |
| GatewayClass | `ferrum` |
| Controller name | `ferrum.io/gateway-controller` |

Kick a manual run with:

```bash
gh workflow run "Gateway API Conformance" \
  --field gateway_api_version=v1.5.1 \
  --field conformance_profile=GATEWAY-HTTP,GATEWAY-GRPC \
  --field supported_features=Gateway,ReferenceGrant,HTTPRoute,GRPCRoute
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
| `Gateway` HTTPS listeners | Yes, as part of `GATEWAY-HTTP` | Terminating listeners materialize every authorized `certificateRefs` entry into per-listener DP frontend TLS sources; the DP serves them all from one SNI-aware resolver (several refs per listener and several Gateways per namespace are both supported) and rejects snapshots if any referenced serving cert/key cannot be loaded. Two listeners claiming one hostname with different certificates fail the loser closed as `Conflicted=True`/`HostnameConflict`. See [frontend_tls.md](frontend_tls.md#gateway-api-multi-certificate-serving-sni). |
| `HTTPRoute` hostname, path, method, header, and query matching | Yes | Translated into proxies plus ordered `mesh_route_dispatch` rules where predicate matching is needed |
| `HTTPRoute` `RequestHeaderModifier` | Yes | Route-level set/add/remove header filters are projected into request-transform rules and verified by black-box backend echo |
| `HTTPRoute` `RequestRedirect` | Yes | Redirect filters materialize action-only dispatch rules with status, hostname, scheme, port, and path replacement support |
| `HTTPRoute` weighted `backendRefs` | Yes | Multiple non-zero backends create a weighted upstream; a rule whose backendRefs are **all** `weight: 0` remains traffic-capturing and returns HTTP 500 through a synthesized fault-abort — see [backendRef port and zero-weight semantics](#backendref-port-and-zero-weight-semantics) |
| Cross-namespace `HTTPRoute.backendRefs` | Yes | Requires an exact `ReferenceGrant`; missing grants are rejected and unresolved |
| Cross-namespace `parentRefs` | Yes | Allowed only when the referenced Gateway listener permits the route namespace (`HTTPRoute`, `GRPCRoute`, `TCPRoute`, and `TLSRoute`). `allowedRoutes.namespaces.selector` is parsed atomically with Kubernetes label-key/value and operator-cardinality validation; a malformed component invalidates the listener and attaches no routes. ReferenceGrant is not used for parentRefs. |
| Invalid backend references | Yes | Missing Services/ServiceImports, unsupported backend target kinds, and unpermitted cross-namespace refs are reported as unresolved and materialize fail-closed HTTP 500 routes |
| MCS `ServiceImport` backendRefs | Partial (Ferrum translation/status; not an upstream conformance feature claim) | GEP-1748 Extended: `group: multicluster.x-k8s.io` / `kind: ServiceImport` resolves through the same typed backend-kind adapter as core `Service`, including ReferenceGrant authorization, port existence checks, ClusterSet DNS (`*.svc.clusterset.local`), and optional MCS-labeled EndpointSlice expansion when pod discovery is enabled. The MCS CRD is watched when present and skipped cleanly when absent. Upstream profiles/features remain unchanged — this is not advertised as a Gateway API conformance claim. |
| Selectorless/headless Services | Yes | With pod discovery enabled, backends resolve ready EndpointSlice addresses directly; a named Service `targetPort` resolves against EndpointSlice port names, but the `backendRef.port` itself is numeric-only — see [backendRef port and zero-weight semantics](#backendref-port-and-zero-weight-semantics) |
| Backend failure | Yes | Traffic to unavailable generated backends must return an error response rather than falling through |
| Route update and deletion | Yes | Reconciliation regenerates live proxy/upstream/plugin config; deletion removes the route from live config |
| `UDPRoute` | Yes, via unit translation/status tests **and** a live UDP data-path integration suite (not upstream `GATEWAY-UDP`; no `kind` black-box step) | A `UDPRoute` attached to a `protocol: UDP` Gateway listener materializes a Ferrum UDP stream proxy on the listener port, preserving datagram semantics from the existing UDP data path (per-client sessions, idle expiry). The opt-in response-amplification guard is **not** engaged — Gateway API has no field for it and the translator leaves `udp_max_response_amplification_factor` unset. CI **Unit** Tests cover parent/listener attachment, ReferenceGrant cross-namespace authorization, weighted multi-backend materialization, zero-weight withdrawal, mixed valid/invalid weighted blackhole legs, missing/unpermitted backend fail-closed behavior, parent status (`Accepted`/`ResolvedRefs`/`Programmed`), live backendRef and weight-only updates, and deletion withdrawal — see [UDPRoute translation](#udproute-translation) and `tests/unit/gateway_core/k8s_udproute_translation_tests.rs`. CI **Integration** Tests then run that translated config through the real UDP runtime (`tests/integration/gateway_api_udproute_datapath_tests.rs`): the translator's own listener port is bound by `start_udp_listener`, a client datagram traverses the generated stream proxy and is answered by the backend the route named, two `UDPRoute`s on two UDP listeners do not cross-talk, a weighted `backendRefs` set is served from its generated upstream with per-session leg stability, and a leg naming an absent `Service` drops the datagram instead of answering it. The Gateway API conformance lab does **not** run a UDPRoute black-box step (Trusted Cross Build Policy freezes adding that executable automation), so the live evidence rides the required `Tests` aggregate instead. Upstream profile/features remain `GATEWAY-HTTP,GATEWAY-GRPC` / `Gateway,ReferenceGrant,HTTPRoute,GRPCRoute`; `GATEWAY-UDP` is **not** claimed on this pin. |
| `BackendTLSPolicy` | Not claimed by upstream conformance profiles | Watched and translated for Service-backed `HTTPRoute`/`GRPCRoute` backends: `validation.hostname` → upstream SNI, `caCertificateRefs` (ConfigMap inline PEM or Secret `k8s://…#ca.crt`) or `wellKnownCACertificates: System` (projected as the first-class `system://` trust source, which pins built-in webpki roots and never falls back to `FERRUM_TLS_CA_BUNDLE_PATH` or inherits `FERRUM_TLS_NO_VERIFY`), optional `subjectAltNames` → SAN allow-list, `backend_scheme: https`. Exactly one `targetRefs` entry is supported per the v1.5.1 implementation guidance; non-empty `spec.options` and malformed optional shapes are rejected. Invalid, conflicting, or partially-covering policies fail closed with an HTTP 500 fault abort — including a rule whose `backendRefs` mix policy-covered and uncovered Services, which Ferrum cannot represent in one upstream. Policy `status.ancestors` names the **targeted Service** as the single Ferrum ancestor (Ferrum's verdict takes no Gateway as input, so it cannot vary per Gateway) and carries `Accepted` / `ResolvedRefs` conditions; precedence losers report `Accepted=False, reason=Conflicted`. Ferrum's own contribution is therefore one entry regardless of how many Gateways route to the Service. `targetRefs[].sectionName` is resolved against the Service's actual `spec.ports[].name`: a `sectionName` that names no port makes the policy fail to attach and reports `Accepted=False, reason=TargetNotFound` with a field-specific message, and — because the intended port cannot be inferred — it neither applies to nor faults the Service's other, valid ports. Per GEP-1897, BackendTLSPolicy applies only to TCP traffic, and eligibility is decided on the port's **transport**: a port qualifies only when `spec.ports[].protocol` is proven `TCP` (omitted counts as TCP, matching the Kubernetes default; the comparison is case-insensitive). `UDP`, `SCTP`, and any unrecognized protocol value are all ineligible — GEP-1897 names UDP in its examples, but the rule it states is that the policy configures TLS for TCP traffic, and no TLS handshake can be originated on an SCTP or unknown-transport port. A policy that explicitly attaches to an ineligible port (a `sectionName` naming a `UDP`, `SCTP`, or unrecognized-protocol port) reports `Accepted=False, reason=Invalid` scoped to that port, leaving sibling TCP ports alone; a Service-wide policy on a Service with no TCP port at all is rejected the same way because it would govern nothing. Route traffic that actually selects a rejected policy fails closed with the HTTP 500 fault rather than originating TLS over a non-TCP transport or dropping to plaintext. A Service that mixes TCP and non-TCP ports is accepted with a warning carried in the `Accepted` condition message and the policy is effective only for the TCP ports; the non-TCP ports keep their pre-policy behaviour. Condition messages name the transport from a fixed set (`TCP` / `UDP` / `SCTP` / "not a recognized Kubernetes protocol") and never echo the raw cluster-supplied `protocol` string. A Service declaring more than 64 ports exceeds Ferrum's bounded port index, so the port transport cannot be proven and every policy targeting it is rejected fail closed. When third-party controllers have filled the CRD's 16-entry `ancestors` limit, Ferrum adds no entry (the spec forbids exceeding it), but translation is unaffected: the policy still applies and covered backends still originate TLS. `status.ancestors` is mutable state owned by other controllers, so letting it gate translation would let any controller with status-write access disable backend TLS origination and fault covered traffic. The consequence of a full ancestor map is therefore a reporting gap for that policy, never a traffic outage and never a drop to plaintext. |
| `ListenerSet` | Yes, via Ferrum unit/integration tests **and** a live black-box lab step (not an upstream feature claim) | Watched optionally (`gateway.networking.k8s.io/v1`, discovery skips when the CRD is absent) and bounded by the same configured source-namespace scope as Gateways and Routes. A `ListenerSet` attaches only when its `parentRef` selects a Ferrum-managed Gateway **and** that Gateway's `spec.allowedListeners.namespaces` permits the ListenerSet namespace (`Same` / `Selector` / `All`; default `None` → `Accepted=False` / `NotAllowed`). Accepted listeners merge into the parent Gateway's programming with precedence Gateway → oldest ListenerSet → `{namespace}/{name}`; hostname/protocol collisions on the same port mark the loser `Conflicted=True` (`HostnameConflict` / `ProtocolConflict`) and never materialize traffic. Routes parentRef the ListenerSet (optionally selecting a listener by `sectionName` or `port`) and reuse the same HTTP/L4 translation engine as Gateway listeners. A cross-namespace ListenerSet remains namespaced to its own resource for identity, route attachment, status, and Secret/ReferenceGrant resolution, while its physical frontend-TLS claim joins the attached Gateway namespace's serving plan. It retains its complete admitted listener-owned certificate set, but cannot mint a process-global default certificate from a namespace with no managed Gateway or make a disjoint-hostname parent listener conflicted merely by naming a different credential. Cross-namespace `certificateRefs` require a ReferenceGrant `from.kind=ListenerSet` (Gateway grants are not inherited). Status emits ListenerSet `Accepted`/`Programmed` plus per-listener conditions, and Gateway `status.attachedListenerSets` counts successfully attached sets. Update/delete withdraws mesh listeners and routes. Upstream profile/features remain `GATEWAY-HTTP,GATEWAY-GRPC` / `Gateway,ReferenceGrant,HTTPRoute,GRPCRoute` — `ListenerSet` is **not** advertised as a supported upstream feature on this pin. Evidence: `tests/unit/gateway_core/k8s_listenerset_translation_tests.rs`, `tests/integration/gateway_api_listenerset_tests.rs`, and `scripts/gateway_api_listenerset_conformance.sh`. |
| `GRPCRoute` | Yes, via upstream `GATEWAY-GRPC` | Watched and translated — see [GRPCRoute predicate translation](#grpcroute-predicate-translation). CI advertises `GRPCRoute` and runs the pinned upstream `GATEWAY-GRPC` core suite (exact method, header, listener hostname, weight, and core status) against a live Ferrum listener. Extended `GRPCRouteNamedRouteRule` is **not** claimed. Native gRPC route misses and `reject_unmatched` refusals map HTTP 404 → gRPC `UNIMPLEMENTED` (official HTTP↔gRPC table / Gateway API `GRPCExactMethodMatching`). |
| `TCPRoute` | Yes, via Ferrum black-box live checks (not upstream `GATEWAY-TCP`) | Lab installs the pinned `v1.5.1` experimental-channel CRD bundle (one coherent channel that includes `TCPRoute`/`TLSRoute`). Live kind traffic proves parent/listener attachment, same-namespace and AllowedRoutes cross-namespace parentRefs, same-namespace and ReferenceGrant cross-namespace backend resolution, tagged TCP echo forwarding, empty/missing/unpermitted backend fail-closed behavior, parent status (`Accepted`/`ResolvedRefs`/`Programmed`), live backendRef updates, AllowedRoutes tighten withdrawal, and deletion withdrawal. A present but non-Gateway parentRef opens no listener; only a genuinely parentless legacy input may use the backend-port fallback. Upstream profiles/features remain `GATEWAY-HTTP,GATEWAY-GRPC` / `Gateway,ReferenceGrant,HTTPRoute,GRPCRoute`; `GATEWAY-TCP` is **not** claimed on this pin (the profile/tests land in later Gateway API releases). |
| `TLSRoute` | Yes, via Ferrum black-box live checks (not upstream `GATEWAY-TLS`) | Live kind traffic proves AllowedRoutes cross-namespace parentRefs plus TLS Passthrough SNI selection (distinct hostnames on one listener → distinct backends; unmatched SNI fails closed), tagged TLS echo forwarding through encrypted passthrough, same-namespace and ReferenceGrant cross-namespace backend resolution, empty/missing/unpermitted backend fail-closed behavior, parent status (`Accepted`/`ResolvedRefs`/`Programmed`) and listener `attachedRoutes`, live backendRef updates, and deletion withdrawal. Translator materializes `passthrough: true` stream proxies (`BackendScheme::Tcp`) keyed by route `hostnames` on Gateway `protocol: TLS` / `tls.mode: Passthrough` listener ports. A present but non-Gateway parentRef opens no listener; only a genuinely parentless legacy input may use the backend-port fallback. The separate `TLSRouteModeTerminate` feature is not implemented or advertised: non-Passthrough TLS listeners are rejected with `Accepted=False` / `UnsupportedProtocol` and never fall back to a backend-port listener. Upstream profiles/features remain `GATEWAY-HTTP,GATEWAY-GRPC` / `Gateway,ReferenceGrant,HTTPRoute,GRPCRoute`; `GATEWAY-TLS` is **not** claimed on this pin. |
| `BackendLBPolicy` / `XBackendTrafficPolicy` session persistence | Partial (Ferrum black-box / translation; not an upstream conformance feature claim) | On the pinned `v1.5.1` experimental channel `BackendLBPolicy` was **removed** and replaced by `XBackendTrafficPolicy` (`gateway.networking.x-k8s.io`). Ferrum watches both shapes: historical `BackendLBPolicy` (`gateway.networking.k8s.io/v1alpha2`) when that CRD is still installed, and `XBackendTrafficPolicy` on the current pin. Representable Cookie `sessionPersistence` projects onto generated route Upstreams as `consistent_hashing` + `hash_on: cookie:…`, forcing Upstream materialization even for single-backend rules so sticky `Set-Cookie` injection runs on the live LB path. Persistence is **backend-bound**, as GEP-1619 requires: the cookie carries an HMAC-authenticated opaque token derived from the namespace-qualified route-scoped upstream identity and the full identity of the target that served the initial response (dial `host:port`, declared Service port / per-port policy lane, tags, locality, and path override — so a traffic split whose `backendRefs` resolve to the same endpoint through different Services or Service ports keeps separate bindings), and a returning request resolves that token through a per-upstream binding index materialized at config reload, returning the client to that exact endpoint (H1/H2, gRPC, WebSocket, and H3/cross-protocol dispatch alike). The process-local authentication key prevents clients from forging tokens from predictable route and endpoint metadata; tokens survive config reload, while a restart or another replica treats them as stale and transparently re-pins the client. The token discloses no backend address, credential, or secret and is never logged. Because the upstream is route-scoped, a token cannot steer traffic across routes, Services, namespaces, or policies. A token that is malformed, oversized, foreign, stale after endpoint removal, outside the selected subset/port lane, or unhealthy is treated as no session: the request re-selects normally and is issued a fresh binding, never bypassing health, subset, port, TLS, authorization, retry, or connection-limit semantics. A retry that legitimately rotates away from a failed endpoint issues the cookie for the endpoint that actually produced the successful response, on every retry-capable dispatch path (H1/H2, direct gRPC, WebSocket including H2 extended CONNECT, native H3, the H3 cross-protocol bridges, and H3 WebSocket); a gateway-synthesized rejection that dialed no backend issues no cookie. A resolved binding is additionally re-validated against the selected target's own per-port policy lane: if that lane is not consistent hashing on the same cookie, the binding fails closed to ordinary selection and reissue. The wire cookie name is deterministically scoped to the route resource and rule (the configured `sessionName` remains its readable prefix), preventing two route rules from sharing one session. Route-rule `sessionPersistence` overrides a Service-targeted policy. For a traffic split where only some Services carry a policy, Ferrum applies the selected persistence configuration to all backends in that rule, one of the behaviors explicitly permitted by GEP-1619; conflicting policy configurations fail closed. `cookieConfig.lifetimeType: Session` emits a browser session cookie (no `Max-Age`) only when `absoluteTimeout` is absent; `Permanent` requires `absoluteTimeout` → `Max-Age`. `idleTimeout`, Session+`absoluteTimeout` (Ferrum cannot enforce an internal absolute lifetime), Header persistence (Ferrum does not synthesize a response token), non-Service `targetRefs`, and `retryConstraint` fail closed with field-specific diagnostics — a policy carrying `retryConstraint` is rejected entirely (`Accepted=False` / `UnsupportedValue`) and no portion of it (including `sessionPersistence`) is applied. Multiple policies targeting the same Service use GEP-713 None-merge / oldest-wins precedence (creationTimestamp, then full resource identity); the winning policy stays `Accepted=True`, and every challenger that loses any Service target is `Accepted=False` / `Conflicted` (validation precedes conflict so an invalid object never becomes Accepted). That rejection is atomic in translation too: a policy that loses any one of its Services is withdrawn from every Service it targets, so only `Accepted=True` policies steer traffic. Policy `status.ancestors` reports `Accepted` / `UnsupportedValue` / `Conflicted`, preserves ancestor entries owned by other Gateway API implementations, and keeps `lastTransitionTime` stable while a condition's value is unchanged. When third-party controllers have filled the shared 16-entry ancestor map, Ferrum adds no entry (the spec forbids exceeding it), but translation is unaffected: session persistence still reaches the data plane. `status.ancestors` is mutable state owned by other controllers, so letting it gate translation would let any controller with status-write access drop stickiness. The consequence of a full ancestor map is therefore a reporting gap for that policy, never a loss of persistence behavior. Upstream profile/features remain unchanged — this is not advertised as a Gateway API conformance claim. |

BackendTLSPolicy ConfigMap CA references require the controller to list/watch
ConfigMaps in every watched namespace. Kubernetes field selectors cannot name a
dynamic set of referenced ConfigMaps, so the reflector's memory use scales with
the namespace's total ConfigMap population, not only the currently referenced
objects. Scope Ferrum's watched namespaces and RBAC accordingly on very large
clusters.

## UDPRoute translation

`UDPRoute` shares the L4 materialization path with `TCPRoute`/`TLSRoute`: the
route carries no request-level predicate, so the Gateway listener port is the
entire match and the rule's `backendRefs` **set** is the weighted datagram peer
set.

| Surface | Behavior |
|---|---|
| Listener attachment | A `UDPRoute` attaches only to a `protocol: UDP` listener. `allowedRoutes.kinds` may narrow it to `UDPRoute`; naming any other kind for a UDP listener invalidates that kinds list, exactly as for TCP/TLS |
| Gateway parents | A `UDPRoute` materializes **only** on concrete listener ports that survive Gateway identity, `sectionName`/`port` selection, listener protocol/kind, `allowedRoutes` namespace, and listener materializability. An unknown, mismatched, or wholly ineligible parent opens nothing (`Accepted=False` with `NoMatchingParent` / `NotAllowedByListeners`) — it never falls back to the backend port |
| Missing / non-Gateway parents | Every `UDPRoute` requires an attached Gateway UDP listener. A route with no `parentRefs`, or whose `parentRefs` name only non-Gateway parents — a GAMMA `Service` parent, a mistyped `kind`, an unrecognized `group` — opens nothing. Present but malformed or explicitly empty `parentRefs` likewise fail closed instead of being reinterpreted as absent. Ferrum implements no non-Gateway parent for `UDPRoute`, and using the backend port would bind an unannounced north-south UDP relay. Parentless `TCPRoute`/`TLSRoute` retain their historical backend-port fallback; `UDPRoute` does not |
| Materialization | One Ferrum stream proxy per rule per attached listener port, `backend_scheme: udp`. With no valid attached Gateway listener, no proxy or generated upstream is created; backendRefs are still fully validated so suppression cannot bypass hostile-input or `ReferenceGrant` checks |
| `spec.rules` | Exactly one rule. The pinned CRD (`apis/v1alpha2/udproute_types.go`: `MinItems=1`, `MaxItems=16`, `listType=atomic`) accepts `1..=16`. Missing, non-array, empty, and over-long (`>16`) `spec.rules` are rejected fail closed as `Accepted=False` / **`Invalid`**. A CRD-valid `2..=16`-rule object is rejected fail closed as `Accepted=False` / **`UnsupportedValue`** (the upstream reason constant), never `Invalid`, with a `UDPRoute spec.rules` diagnostic naming the upstream bound and Ferrum's own. Why unrepresentable rather than merged: a `UDPRouteRule` has only `name` and `backendRefs`, so it carries no match predicate — N rules are N indistinguishable matches on one listener port with no standards-defined precedence, and weights are declared *within* a rule and are not comparable across rules. Merging the sets would silently turn a two-rule object into one weighted split; materializing both would queue competing OS listeners whose winner is bind order. See [`ensure_udp_route_rule_shape`](../src/config_sources/k8s/gateway_api.rs) |
| `rules[].backendRefs` | Required array with `MinItems=1` / `MaxItems=16`. Missing, non-array, and empty `backendRefs` reject fail closed as `Accepted=False` / **`Invalid`** (same CRD bound as `spec.rules`) |
| `backendRefs[].port` | **Required** and numeric `1..=65535` on every entry — including `weight: 0` entries; absent or out-of-range fails closed with a `UDPRoute backendRefs[].port` diagnostic |
| `backendRefs[]` target | Core `Service` only; any other group/kind fails the whole rule closed. The set is bounded at 16 entries, matching the CRD |
| Same-listener conflict | Two `UDPRoute` objects that resolve to the same concrete UDP Gateway listener are arbitrated by oldest `metadata.creationTimestamp`, then `{namespace}/{name}`. Arbitration is listener-identity scoped (a wildcard parentRef and a `sectionName`/`port` selector naming one listener conflict); distinct listeners stay independent. The loser emits neither a proxy nor a generated upstream for the conflicted listener. Per the upstream multiple-route attachment contract both otherwise-valid routes stay `Accepted=True`; only the oldest is effective (`Programmed=True`), while the shadowed newer route reports `Programmed=False` with conflict evidence (Ferrum also sets `Conflicted=True`). A multi-listener route that loses on only some listeners keeps the non-colliding listeners (`Accepted=True` / `Programmed=True`, with supplementary `Conflicted=True` for the partial loss — fail-closed per listener, no duplicate port bind). Listener `attachedRoutes` counts every accepted attached `UDPRoute`, including a non-effective newer route |
| Backend set | One serviceable leg dispatches directly to `<service>.<namespace>.svc.<cluster-domain>:<port>`. Two or more non-zero-weight legs materialize one namespaced Ferrum upstream whose weighted targets preserve the **declared relative weights** (omitted weight defaults to `1`) |
| Selection granularity | Per UDP **session** (client 5-tuple), not per datagram: Ferrum's UDP data path selects a target once per session and reuses it for that session's lifetime. Distribution therefore converges over sessions, not over individual packets |
| Weights | `weight: 0` removes a leg from the target set entirely; a rule whose backendRefs are all `weight: 0` materializes nothing and warns. Gateway API's full `0..=1000000` range is accepted; values over Ferrum's internal `65535` target-weight ceiling are normalized proportionally across the resolved set. A value above `1000000` or of any non-integer shape fails closed |
| Invalid legs | A leg naming a missing `Service`, or a `Service` without the referenced port, **keeps its declared weight** and is pointed at an unresolvable blackhole target, so its share of sessions fails closed. Weight is never renormalized onto the resolvable legs. `ResolvedRefs=False` is reported for the route |
| Cross-namespace `backendRefs` | Requires an exact `ReferenceGrant` (`from` `gateway.networking.k8s.io`/`UDPRoute`, `to` core `Service`); a missing or mismatched grant fails the **whole rule** closed (the strongest fail-closed outcome) and reports `ResolvedRefs=False` |
| Cross-namespace `parentRefs` | Rejected, matching `TCPRoute`/`TLSRoute` — Ferrum has no L4 cross-namespace parent materialization yet |
| `spec.hostnames` | Not a Gateway API `UDPRoute` field, and a datagram carries no name to match on. A hostname supplied through a non-Kubernetes config source is rejected fail closed rather than silently ignored |
| Status | `status.parents[]` carries Ferrum-authored `Accepted`, `ResolvedRefs`, `Programmed`, and `Conflicted`, written through the same read-modify-write path as every other route kind. A fully shadowed same-listener UDPRoute loser stays `Accepted=True` / reason `Accepted` (attached) and reports `Programmed=False` with conflict evidence plus `Conflicted=True`; it is not flipped to `Accepted=False` for losing traffic ownership |
| Update / delete | Reconciliation regenerates live stream listeners and upstreams from the full snapshot; a changed `backendRefs` or a weight-only change replaces the upstream's target set under the same deterministic id, a deleted `UDPRoute` withdraws both the listener and its upstream, and deleting a conflict winner lets a previously suppressed loser materialize on the next reconcile |

Datagram semantics come from the existing Ferrum UDP data path and are not
re-implemented for Gateway API: sessions are keyed by client address with an
idle timeout.

The response-amplification guard is **not** engaged for a generated `UDPRoute`
proxy. That guard is the opt-in per-proxy `udp_max_response_amplification_factor`
(default unset — see
[`docs/tcp_udp_proxy.md`](tcp_udp_proxy.md)), Gateway API defines no field that
maps onto it, and the translator leaves it unset, exactly as a hand-authored UDP
proxy that does not set it. An internet-facing `UDPRoute` relay therefore has no
response-size ceiling relative to the request that triggered it; operators who
need one must front the listener with their own control, because a
Kubernetes-managed proxy is regenerated from the route on every reconcile and
cannot carry a hand-applied override.

Support boundary, stated exactly: Ferrum implements Gateway API `UDPRoute` with
a **single** rule, a weighted `backendRefs` set of up to 16 core `Service`
legs, and session-granular weighted selection. Ferrum does **not** claim
packet-level weighted drop precision, `ServiceImport` or any other
implementation-specific backend kind, or the upstream `GATEWAY-UDP` conformance
profile. The `spec.rules` limit is the one place where Ferrum declines an
upstream-valid object rather than rejecting a malformed one, and it is reported
that way — `Accepted=False` / `UnsupportedValue` on `spec.rules`, with
`ResolvedRefs` still evaluated on its own terms — so an operator can tell
"Ferrum will not serve this" from "this object is broken".

### Evidence

| Claim | Gate |
|---|---|
| Translation, admission, weighted sets, ReferenceGrant, status, same-listener conflict arbitration, update/delete | CI **Unit Tests** — `tests/unit/gateway_core/k8s_udproute_translation_tests.rs` |
| A translated `UDPRoute` binds a real UDP listener and a datagram reaches the backend it named, and returns | CI **Integration Tests** — `tests/integration/gateway_api_udproute_datapath_tests.rs`, shard `protocols-data-plane` |
| Two `UDPRoute`s on two UDP listeners serve only their own backends | same integration suite |
| A weighted `backendRefs` set is served live from its generated upstream, one leg per session for that session's lifetime | same integration suite |
| A leg naming an absent `Service` drops the datagram instead of answering it | same integration suite |
| Upstream `kind` black-box conformance for UDP | **not run** — the Trusted Cross Build Policy freezes adding that executable automation to the lab, so `GATEWAY-UDP` is not claimed |

The integration suite uses the production translator and the production
`start_udp_listener`; the only test-side substitution is a DNS override that
points the generated `<service>.<namespace>.svc.cluster.local` names at
loopback, where the pre-bound test backends listen.

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
  materialized-parent record for the overlapping `(parentRef, listener)`
  claims. Sibling claims on other listeners are retained once port-aware
  representation applies. The overlapping claim is reported `Accepted=False`
  with `reason: Conflicted` (when every claim under that parentRef lost) or the
  parent stays `Accepted=True` when at least one listener claim survives, with
  a message naming the winner on the conflicting listener.
- Overlap is detected per listener and per hostname intersection. The resulting
  acceptance decision is per-`(parentRef, listener)`: a loss on one listener
  does not withdraw healthy sibling claims.
- Rejection does not cascade: Routes are considered once in the total Gateway
  API order, and a Route withdrawn after a loss on one listener is never
  admitted as a winner on that same listener. A later Route is therefore
  unaffected when it overlaps only that already-rejected claim.

"The same listener" means the **resolved** listener, not the literal
`parentRefs[]` entry. A parentRef is a selector, so the two are not
interchangeable:

- A wildcard reference (no `sectionName`, no `port`) and a reference pinning that
  listener by `sectionName` or `port` attach to the same listener and therefore
  contend, even though their selector shapes differ.
- Two wildcard references on one Gateway that `allowedRoutes.kinds` sends to
  *different* listeners never share one, so neither is rejected.
- ParentRefs are not independent acceptance compartments inside one Route for
  *unresolved* selectors, but once Ferrum can stamp a listener port onto the
  materialized proxy, a cross-kind loss is confined to the overlapping
  `(parentRef, listener)` claim. Surviving claims on other listeners keep their
  proxies and remain `Accepted` when at least one claim is programmed. Route
  status still echoes each parentRef the operator wrote — listener resolution
  is an internal arbitration detail.

Same-kind behavior is unchanged: two HTTPRoutes (or two GRPCRoutes) sharing a
`(hostname, listen path, listen_port)` still collapse into one ordered
dispatch-rule list, and only claim-for-claim collisions are resolved as
conflicts.

**Port-aware route representation.** Ferrum materializes Gateway API HTTP-family
routes with the admitting listener's identity, so listeners of one Gateway are
distinguishable both in the route table and on the wire:

- The admitting listener's port is stamped on `Proxy.listen_port`, and its TLS
  class on the namespace-qualified `GatewayConfig.http_tls_listen_ports`
  (`(namespace, port)`). Both are read from **that listener's own policy** — a
  sibling listener sharing a port number never reclassifies another's routes.
- A declared Gateway `parentRef` that resolves no concrete, materializable
  listener — an absent Gateway, a hostname / sectionName / port / policy gate
  that clears no listener — materializes **nothing** for that parent (no proxy,
  upstream, plugin, or materialized-parent record) and contributes **no**
  HTTPRoute/GRPCRoute conflict key or cross-kind arbitration claim. Status stays
  `Accepted=False` with `NoMatchingParent` / `NotAllowedByListeners` /
  `NoMatchingListenerHostname` rather than `Programmed` or `Conflicted`. The
  listener-less, port-agnostic claim (and its cross-kind arbitration) survives
  only for the deliberately parentless legacy shape (`spec.parentRefs` absent).
- `GatewayListenerManager` (`src/proxy/gateway_listener.rs`) binds a real
  socket for every declared listener port in `file`, `database`, and `dp` mode,
  alongside the global `FERRUM_PROXY_HTTP_PORT` / `FERRUM_PROXY_HTTPS_PORT`
  sockets. Two same-protocol listeners such as `:80` and `:8080` therefore both
  serve, and each request matches only the route attached to the listener it
  arrived on.
- Two routes that share `(hostname, listen path)` on **different** listeners
  validate and serve independently. Overlapping host+path on the **same**
  listener still fails closed at config validation
  (`Overlapping host+listen_path`) with field-specific Gateway API status
  diagnostics.
- A Route that loses cross-kind arbitration on one listener retains healthy
  sibling claims on other listeners. The arbitration domain is the resolved
  `GatewayApiListenerKey`, not the numeric port, so sibling listeners that
  merely share a port are independent.
- Same-kind route merging keys on the **exact admitting listener**, never on the
  numeric port. Two Gateways (or two sibling listeners) sharing a port never
  have their dispatch rules or default backends combined, because Gateway API
  attached each Route to only one of them. If two different listeners would
  materialize the *same* `(namespace, hosts, listen path, listen port)` slot,
  that claim is physically ambiguous — one socket, one route-table slot, two
  contracts — so **both** sides are refused with a translator warning rather
  than letting observation order decide. Same-port listeners with disjoint
  hostnames are unaffected and keep serving independently.
- **That refusal is carried into Route status, not only into the data plane.**
  Every refused claim marks its `status.parents[]` entry `Conflicted=True` with
  a message naming the refused listener by identity. When the parentRef has no
  surviving claim left — no other listener, no other rule or path — it also
  reports `Accepted=False` and `Programmed=False` with `reason: Conflicted`, so
  a Route can never advertise a materialized Ferrum parent for a slot the
  translator withdrew. A parentRef that still serves through a sibling listener
  or a sibling claim stays `Accepted=True` / `Programmed=True` and reports only
  the conflict; other parentRefs of the same Route, and `status.parents[]`
  entries owned by other controllers, are untouched. Both colliding Routes are
  reported identically regardless of the order the objects are observed in.
- A numeric port claimed by two listeners with incompatible physical shapes is
  refused at admission, and **every physically competing effective claim fails
  closed** (matching the Gateway API `Conflicted` condition) rather than one
  silently winning the socket. Exactly two shapes qualify:
  - **plaintext vs an effective TLS-serving claim on one port**
    (`ProtocolConflict`). A socket is one or the other. Unresolved or
    listeners with unresolved or unauthorized certificate groups do not count
    as effective TLS claims and cannot poison a healthy plaintext slot.
  - **effective TLS serving plans from more than one Gateway namespace that
    resolve to different complete credential sets** (`HostnameConflict`).
    Ferrum retains every admitted listener-owned certificate as an SNI
    candidate within a Gateway namespace. Across namespaces there is no
    further arbitration, so disagreeing complete sets would make one socket
    present a foreign Gateway's certificate.

  Differing `tls.certificateRefs` on their own are deliberately **not** a
  conflict. Gateway API v1.5.1 defines HTTP-family listener distinctness on
  `(port, hostname)` and states that "the `tls` field is not used for
  determining if a listener is distinct", so sibling HTTPS listeners on one port
  with disjoint hostnames and different `certificateRefs` stay `Accepted`.
  Within a namespace, disjoint hostname listeners retain their complete
  listener-owned certificate groups and materialize independently through SNI
  selection. An unresolved, unauthorized, oversized, or hostname-colliding
  group is withdrawn atomically rather than partially served.
  A cross-namespace ListenerSet competes in its attached Gateway namespace's
  physical plan rather than its own resource namespace. Its admitted
  listener-owned certificates can extend that plan, but it cannot mint a
  process-global default certificate from a namespace that contains no managed
  Gateway.

**Listener lifecycle and its bounds.** The listener set is reconciled on every
config publication, so reload / update / delete / withdrawal reach the sockets
without a restart. These bounds are deliberate and tested:

- **Routing admission is generation-bound.** The atomic `RequestEpoch` that
  publishes a new route table also publishes that generation's listener
  admission as pending. Every listener-scoped route in the pending generation
  fails closed on exact, prefix, regex, cached, global-socket, and
  single-listener-remap lookups. Reconcile derives its decision from that exact
  config snapshot and acknowledges only while the same config generation is
  still current; a stale pass is discarded and the latest generation is
  reconciled immediately. This prevents a new route table from borrowing an
  older generation's successful listener decision while preserving complete
  prior snapshots for requests already in flight.

- **Withdrawal is fail-closed but not instantaneous at the socket.** Routes are
  withdrawn by the atomic config swap that *precedes* the listener reconcile, so
  a withdrawn listener's port answers `404` from that instant — it can never
  stale-route. The socket itself stops accepting as soon as the accept loop
  observes its per-listener shutdown signal and then drains in-flight requests
  under the normal graceful-shutdown budget.
- **A listener port that cannot be bound is reported, not fatal.** A same-class
  process-global proxy frontend on the exact requested port already satisfies
  the Gateway listener: the router sees that accepted port, so the dynamic
  manager binds no duplicate socket and reports no failure. A wrong-class
  global proxy frontend, an admin / control-plane listener, or a TCP/TLS stream
  proxy on the port is refused; a port the process lacks permission to bind
  (`:80` / `:443` without `CAP_NET_BIND_SERVICE`) fails and is retried. Either
  way the failure is logged and surfaced on
  `GatewayListenerManager::bind_failures`, and routes scoped to a genuinely
  refused or bind-failed listener stay unreachable rather than being served
  somewhere else. Once the matching generation is acknowledged, both admission
  refusals and ordinary OS bind failures suppress the intentional
  Service-fronted remap.
- **An HTTP↔HTTPS class flip retires the old generation first.** The retiring
  accept-loop task is awaited before the replacement binds, so with
  `FERRUM_ACCEPT_THREADS > 1` the `SO_REUSEPORT` sockets of the two classes
  never coexist on one port. Already accepted connections keep draining.
- **A listener that stops serving is rebound.** A started listener whose accept
  loop later ends — cleanly, with an error, or by panic — is reaped on the next
  reconcile, surfaced as a bind failure, and rebound; finished drains are reaped
  too, so completed handles never accumulate for the life of the process.

**Listener status for a refused port.** The same-port incompatible-shape
refusal is reported on the Gateway's own `status.listeners[]` entry, not only as
a translator warning: every refused effective claim reports `Conflicted=True`
(`ProtocolConflict` for plaintext-vs-effective-TLS, `HostnameConflict` for
cross-namespace effective TLS slots that resolve to different credentials),
`Accepted=False` with `PortUnavailable`, and `Programmed=False`. `ResolvedRefs`
still describes that listener's own references, which the port conflict does not
invalidate. A listener that is merely a same-namespace TLS sibling with a
different `certificateRef` is not refused for that reason alone and keeps its
ordinary status while materializing with its own SNI candidate.

**HTTP/3 on Gateway listener ports.** When `FERRUM_ENABLE_HTTP3=true` and
frontend TLS is configured, every TLS-class Gateway listener port also gets its
own QUIC socket, added, withdrawn and class-flipped with its TCP listener. Two
TLS listener ports are therefore reachable over HTTP/3 as well as HTTP/1.1 and
HTTP/2. `Alt-Svc` is advertised per frontend port and only where a QUIC socket
really exists, so a client is never steered from a port-scoped listener to the
global HTTPS port whose route table cannot match the port-scoped route. A port
whose QUIC bind fails keeps serving H1/H2, reports the failure on
`GatewayListenerManager::bind_failures`, advertises no HTTP/3, and is retried.

A UDP/DTLS stream proxy on the same **numeric** port is a QUIC-only conflict:
TCP and UDP are independent socket namespaces, so the HTTPS TCP listener stays
bound and keeps serving H1/H2. The optional QUIC half is refused with a bounded
`udp_stream_collision` reason, `ensure_quic` is not called while the claim
exists, and the TCP port is **not** added to the whole-listener refused-route
set. Adding the UDP/DTLS claim on reload drains only QUIC (existing H1/H2
connections continue); removing it starts QUIC on the already-running TCP
listener. A stale reconcile cannot restore QUIC after a newer epoch reserved
the UDP port. TCP/TLS raw-stream collisions still refuse the whole HTTP-family
listener; plaintext HTTP listeners remain unaffected by UDP/DTLS same-port
claims.

**Single-listener protocol remap.** When the whole route table declares exactly
one listener port of a protocol class, a request arriving on the global process
bind of that class is also served by it. This exists for the Service-fronted
topology, where a `Service` maps the Gateway listener port (`:80`) onto the
pod's `FERRUM_PROXY_HTTP_PORT` (`:8000`) and the listener port is never bound
inside the pod. With two or more same-class listener ports the remap is off and
only an exact listener match serves, because the request would otherwise be
ambiguous.

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

- **Invalid / unresolved backendRef** (missing Service or ServiceImport, unsupported backend
  kind, or an unpermitted cross-namespace ref) materializes a fail-closed route
  that returns **HTTP 500**, matching the Gateway API expectation. The
  black-box lab asserts the `/invalid` route returns `500`.
- **MCS `ServiceImport` backendRefs** (`group: multicluster.x-k8s.io`) resolve
  through the shared backend-kind adapter to ClusterSet DNS
  (`{name}.{namespace}.svc.clusterset.local`) or ready EndpointSlice addresses
  labeled `multicluster.kubernetes.io/service-name`. Cross-namespace imports
  require a ReferenceGrant whose `to` names that group/kind. Missing imports and
  unknown kinds stay fail-closed with `ResolvedRefs=False`
  (`BackendNotFound` / `InvalidKind`).
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
- A routable Ferrum data-plane deployment and NodePort Service mapped to host ports 80 and 443 (HTTP/HTTPS) plus dedicated TCPRoute stream ports `9001`–`9005` and TLSRoute Passthrough stream ports `9011`–`9014` in kind.
- HTTP echo backend namespaces, the upstream suite's gRPC echo-basic fixtures,
  plus tagged TCP and TLS echo fixtures for live `TCPRoute` / `TLSRoute` checks.
- `GatewayClass`, `Gateway`, `HTTPRoute`, `GRPCRoute`, `TCPRoute`, `TLSRoute`, and `ReferenceGrant` resources for direct black-box checks.
- The upstream Gateway API conformance suite pinned by `GATEWAY_API_VERSION`, defaulting to `v1.5.1`, running the complete `GATEWAY-HTTP` and `GATEWAY-GRPC` profiles with explicit supported features `Gateway,ReferenceGrant,HTTPRoute,GRPCRoute`. TCPRoute/TLSRoute remain gated by Ferrum black-box evidence, not by advertising upstream `GATEWAY-TCP` / `GATEWAY-TLS` profiles on this pin.

Direct black-box checks cover hostname, path, method, headers, weighted backend selection, zero-weight-only HTTP 500 behavior, cross-namespace references, invalid references, backend failure, TLS, route updates, and route deletion for HTTP, plus TCPRoute parent/listener attachment, AllowedRoutes cross-namespace parentRefs (attach + tighten withdrawal), ReferenceGrant backend resolution, tagged echo traffic, fail-closed empty/missing/unpermitted backends, status, update, and deletion, plus TLSRoute AllowedRoutes cross-namespace parentRefs, Passthrough SNI selection, ReferenceGrant backend resolution, tagged TLS echo traffic, unmatched-SNI and empty/missing/unpermitted backend fail-closed behavior, status, update, and deletion, plus ListenerSet allowedListeners attachment, HTTPRoute parentRef traffic, NotAllowed default, Gateway `attachedListenerSets`, and delete withdrawal. The pinned upstream suite owns live GRPCRoute conformance evidence. Diagnostics and the upstream conformance report are uploaded from `conformance-results/` as retained CI artifacts.

Lab bootstrap uses `scripts/gateway_api_conformance_lab_setup.sh` (kind ports, experimental CRDs, TCP/TLS listener Service ports). HTTP/GRPC upstream and black-box phases stay in `scripts/gateway_api_data_plane_conformance.sh`; TCPRoute, TLSRoute, and ListenerSet black-box and supplemental diagnostics run via `scripts/gateway_api_tcproute_conformance.sh`, `scripts/gateway_api_tlsroute_conformance.sh`, and `scripts/gateway_api_listenerset_conformance.sh` so the Trusted Cross Build Policy frozen `gateway_api_data_plane_conformance.sh` surface on `main` stays untouched. `UDPRoute` evidence stays in the required `Tests` aggregate — translation/status/lifecycle in the Unit Tests job (`tests/unit/gateway_core/k8s_udproute_translation_tests.rs`) and the live UDP data path in the `protocols-data-plane` integration shard (`tests/integration/gateway_api_udproute_datapath_tests.rs`); this workflow does not add UDPRoute executable automation under the Trusted Cross Build Policy.

The standalone Gateway API conformance workflow triggers on every PR, but a lightweight `changes` job gates the heavy lab job internally: it runs the conformance suite only when the PR diff touches routing, Kubernetes translation/status, CP/DP sync, data-plane startup, plugins, charts, the conformance script, or related CI files, and otherwise skips it. Artifacts are retained for 90 days so the standard upstream report can be reproduced from the workflow inputs and preserved as release evidence.

## Status emission scope

Ferrum's Kubernetes controller patches Gateway API status across every level the
`GATEWAY-HTTP` / `GATEWAY-GRPC` profiles exercise:

| Surface | Status |
|---|---|
| GatewayClass status (`Accepted`, `SupportedVersion`) | Emitted |
| Gateway top-level status (`Accepted`, `Programmed`, `ResolvedRefs`, `Conflicted`) | Emitted |
| Gateway listener-level status (`status.listeners[].conditions`, `attachedRoutes`, `supportedKinds`) | **Emitted** — `attachedRoutes` is a computed count and `supportedKinds` is derived from listener protocol + `allowedRoutes.kinds` |
| Gateway `status.attachedListenerSets` | Emitted — count of ListenerSets with valid parentRef, permitted by `allowedListeners`, and `Accepted=True` |
| Gateway `status.addresses` | Emitted when `FERRUM_GATEWAY_API_STATUS_ADDRESS` is set |
| HTTPRoute / GRPCRoute parent status (`Accepted`, `ResolvedRefs`, `Programmed`, `Conflicted`) | Emitted |
| ListenerSet status (`Accepted`, `Programmed`, per-listener conditions including `Conflicted`) | Emitted when the ListenerSet CRD is installed and Ferrum watches it |
| TLSRoute / TCPRoute parent status | Emitted for watched L4 routes |

GatewayClass, Gateway, and ListenerSet status updates use Kubernetes server-side
apply with the stable field manager `ferrum.io/gateway-controller`. Their
structural condition and listener lists are keyed list-maps, so the minimal
apply document can own Ferrum's entries without copying or claiming another
manager's fields. The ListenerSet document is limited to Ferrum's
`Accepted`/`Programmed` conditions and the listener entries it reconciles.
Ferrum sets `force=true` to reclaim the status fields it continuously
reconciles after upgrades or legacy merge-patch writes.

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
strings should allowlist them; the `GATEWAY-HTTP` / `GATEWAY-GRPC` profiles
themselves assert condition **status**, not custom reason strings.

## Artifacts

Each run uploads a `gateway-api-conformance-<version>` bundle from
`conformance-results/` (90-day retention), produced by
`scripts/gateway_api_data_plane_conformance.sh diagnostics` (plus
`scripts/gateway_api_tcproute_conformance.sh diagnostics` and
`scripts/gateway_api_tlsroute_conformance.sh diagnostics` for L4 log
snapshots and the extended `gateway-api-resources.yaml`):

| File | What it is |
| --- | --- |
| `gateway-api-conformance-test.json` | Streaming `go test -json` events for every upstream conformance test. |
| `gateway-api-conformance-report.yaml` | Upstream `conformance.gateway.networking.k8s.io` report; `profiles[].coreTests` has pass/fail per test. |
| `gateway-api-blackbox.md` | Results of the direct black-box traffic checks (HTTP host/method/header/modifier/cross-namespace/redirect/weighted/invalid-500/zero-weight-500/no-endpoints/update/delete/TLS, plus TCPRoute attachment/status/echo/ReferenceGrant/cross-namespace-parentRef/fail-closed/update/delete, plus TLSRoute Passthrough SNI selection/status/echo/ReferenceGrant/cross-namespace-parentRef/fail-closed/update/delete). GRPCRoute results are recorded in the upstream conformance report. |
| `gateway-api-resources.yaml` | `kubectl get gatewayclasses,gateways,httproutes,grpcroutes,tcproutes,tlsroutes,referencegrants -A -o yaml` snapshot. |
| `kubernetes-workloads.txt`, `namespaces.txt`, `ferrum-*-deployment.txt`, `ferrum-pods.txt`, `ferrum-events.txt` | Cluster/workload diagnostics. |
| `ferrum-control-plane.log`, `ferrum-control-plane-previous.log`, `ferrum-data-plane.log`, `blackbox-*.log` | Container logs. |
| `CONFORMANCE.md` (run-local) | Per-run metadata (version, profile, features, data-plane Service, artifact list). Generated by the script — distinct from the repo-root [`CONFORMANCE.md`](../CONFORMANCE.md). |

## In-process Istio + xDS suite

The second compatibility surface — Istio `networking.istio.io` /
`security.istio.io` CRDs plus the xDS type URLs Ferrum subscribes to — is
covered by the in-process `tests/conformance/` suite, documented under
[Istio + xDS Conformance Suite](../CONFORMANCE.md#istio--xds-conformance-suite)
in the repo-root conformance index.
