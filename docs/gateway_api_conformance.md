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
| Supported features | `Gateway,ReferenceGrant,HTTPRoute,GRPCRoute,HTTPRouteResponseHeaderModification,HTTPRoutePathRewrite,HTTPRouteHostRewrite,HTTPRouteRequestTimeout,HTTPRouteBackendTimeout` |
| GatewayClass | `ferrum` |
| Controller name | `ferrum.io/gateway-controller` |

**Known deviations in the declared rule-timeout features** (details in
[Rule timeouts](#rule-timeouts)). The upstream tests pass; these are the places
where Ferrum's behavior differs from the upstream field definitions:

- `HTTPRouteBackendTimeout`: upstream v1.5.1 defines `backendRequest` as the
  time from when a request starts being sent to the backend until its full
  response has been received. Ferrum bounds each attempt's wait for the
  response head and every idle gap between response frames, **not** the
  attempt's total duration: a backend that keeps trickling its body inside the
  idle gap is not cut per attempt. Only `request` cuts such a body, and a rule
  with `request` unset or `0s` has no total bound at all.
- `HTTPRouteRequestTimeout`: native HTTP/3 cannot enforce `request` on a
  non-gRPC request, so it refuses that request with `503` instead. Ferrum
  withholds the HTTP/3 `Alt-Svc` advertisement on every listener port that
  serves such a rule, so it never steers a client onto the refusal; HTTP/1.1 and
  HTTP/2 enforce `request` fully.

Kick a manual run with:

```bash
gh workflow run "Gateway API Conformance" \
  --field gateway_api_version=v1.5.1 \
  --field conformance_profile=GATEWAY-HTTP,GATEWAY-GRPC \
  --field supported_features=Gateway,ReferenceGrant,HTTPRoute,GRPCRoute,HTTPRouteResponseHeaderModification,HTTPRoutePathRewrite,HTTPRouteHostRewrite,HTTPRouteRequestTimeout,HTTPRouteBackendTimeout
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
| `HTTPRoute` / `GRPCRoute` `ResponseHeaderModifier` | Yes | Rule-level set/add/remove response-header filters are projected into route-local response-transform rules applied by a generated `response_transformer` consumer, and verified through the data plane on both kinds. Upstream `set` overwrites and `add` appends to an existing value. The generated consumer is additive to a same-name **global** `response_transformer`: global static rules run first, the matched route's rules run last and win on a shared name. A filter naming a protocol-managed (hop-by-hop or framing) response field, or setting, adding or removing a gRPC terminal status field (`grpc-status` / `grpc-message` / `grpc-status-details-bin`), is refused at admission. **Trailer cost:** a route override can name any field at request time, so the requests a filtered rule matches drop their non-reserved backend trailers. The generated consumer's trailer policy is request-conditional: sibling rules, and other routes merged onto the same proxy, that declare no response-header filter keep their trailers. For a native gRPC call the initial metadata is modified while `grpc-status` / `grpc-message` / `grpc-status-details-bin`, the message and streaming are preserved; application trailers on that rule are not. `ResponseHeaderModifier` never modifies trailers on any kind. See [ResponseHeaderModifier and response trailers](#responseheadermodifier-and-response-trailers) |
| `HTTPRoute` `URLRewrite` | Yes | `hostname` rebases the backend-facing `Host` / `:authority` (backend selection, SNI, and `BackendTLSPolicy` are unaffected — the rewrite changes the forwarded authority only). `path.type: ReplaceFullPath` replaces the whole path; `path.type: ReplacePrefixMatch` replaces the matched `PathPrefix` and preserves the untouched suffix and the query string, reproducing the upstream rewrite table (`/foo/` and `/foo` rewrite identically, an empty replacement normalizes to `/`, and the root `PathPrefix: /` prepends rather than replacing). `ReplacePrefixMatch` requires every match in the rule to be a `PathPrefix` match. Gateway API proxies never strip their `listen_path` and carry no backend path prefix, so the rewrite is the only path mutation. `URLRewrite` is HTTPRoute-only upstream and stays refused on `GRPCRoute`, and combining it with `RequestRedirect` in one rule is refused rather than silently dropping one action. An HTTPRoute rule with no `backendRefs` whose only filters are `URLRewrite` and/or header modifiers answers HTTP 500, as upstream requires for a rule that forwards nowhere |
| `HTTPRoute` rule `timeouts` (`request`, `backendRequest`) | Yes (`HTTPRouteRequestTimeout`, `HTTPRouteBackendTimeout`) | Standard-channel rule field, validated exactly as the pinned CRD does (GEP-2257 duration grammar; a non-zero `request` bounds `backendRequest`). `backendRequest` bounds ONE backend attempt; `request` is ONE absolute budget for the whole transaction — every attempt, retry backoff, and the streaming response body. Both stay on the rule's own dispatch entry, never on the shared proxy or upstream. `0s` disables either bound. Known deviations: `backendRequest` bounds the response-head wait and idle gaps of an attempt rather than its total duration, and native HTTP/3 cannot enforce `request` on a non-gRPC request yet, so it refuses such a request with `503` rather than serving it unbounded — and HTTP/3 is not advertised (`Alt-Svc`) on a listener port that serves such a rule. See [Rule timeouts](#rule-timeouts). GRPCRoute defines no `timeouts`; `retry` (experimental) stays refused on both kinds |
| `HTTPRoute` weighted `backendRefs` | Yes | Multiple non-zero backends create a weighted upstream; a rule whose backendRefs are **all** `weight: 0` remains traffic-capturing and returns HTTP 500 through a synthesized fault-abort — see [backendRef port and zero-weight semantics](#backendref-port-and-zero-weight-semantics) |
| Cross-namespace `HTTPRoute.backendRefs` | Yes | Requires an exact `ReferenceGrant`; missing grants are rejected and unresolved |
| Cross-namespace `parentRefs` | Yes | Allowed only when the referenced Gateway listener permits the route namespace (`HTTPRoute`, `GRPCRoute`, `TCPRoute`, and `TLSRoute`). `allowedRoutes.namespaces.selector` is parsed atomically with Kubernetes label-key/value and operator-cardinality validation; a malformed component invalidates the listener and attaches no routes. ReferenceGrant is not used for parentRefs. |
| Invalid backend references | Yes | Missing Services/ServiceImports, unsupported backend target kinds, and unpermitted cross-namespace refs are reported as unresolved and materialize fail-closed HTTP 500 routes |
| MCS `ServiceImport` backendRefs | Partial (Ferrum translation/status; not an upstream conformance feature claim) | GEP-1748 Extended: `group: multicluster.x-k8s.io` / `kind: ServiceImport` resolves through the same typed backend-kind adapter as core `Service`, including ReferenceGrant authorization, port existence checks, ClusterSet DNS (`*.svc.clusterset.local`), and optional MCS-labeled EndpointSlice expansion when pod discovery is enabled. The MCS CRD is watched when present and skipped cleanly when absent. Upstream profiles/features remain unchanged — this is not advertised as a Gateway API conformance claim. |
| Selectorless/headless Services | Yes | With pod discovery enabled, backends resolve ready EndpointSlice addresses directly; a named Service `targetPort` resolves against EndpointSlice port names, but the `backendRef.port` itself is numeric-only — see [backendRef port and zero-weight semantics](#backendref-port-and-zero-weight-semantics). When slices are not yet ready, ClusterIP Services fall back to Service DNS on `backendRefs[].port` (kube-proxy DNAT), while headless Services fall back to Service DNS on `targetPort` because CoreDNS returns pod IPs that listen on the container port. |
| Backend failure | Yes | Traffic to unavailable generated backends must return an error response rather than falling through |
| Route update and deletion | Yes | Reconciliation regenerates live proxy/upstream/plugin config; deletion removes the route from live config |
| `UDPRoute` | Yes, via unit translation/status tests **and** a live UDP data-path integration suite (not upstream `GATEWAY-UDP`; no `kind` black-box step) | A `UDPRoute` attached to a `protocol: UDP` Gateway listener materializes a Ferrum UDP stream proxy on the listener port, preserving datagram semantics from the existing UDP data path (per-client sessions, idle expiry). Response-amplification protection is always engaged: the translator projects a finite controller default of `8.0` unless a Ferrum `UDPResponseAmplificationPolicy` wins (UDPRoute > Gateway listener `sectionName` > Gateway > `GatewayClass.parametersRef` > default). Distinct Gateways/listeners that share one UDP port share one physical proxy: each claim is resolved independently, then fail-closed aggregated (finite dominates Unlimited; smallest finite wins; Unlimited only if every represented claim is explicitly Unlimited). Unlimited requires `mode: Unlimited` and `acknowledgeUnsafeAmplification: true`. Invalid or unauthorized policy never programs an unlimited relay. CI **Unit** Tests cover parent/listener attachment, ReferenceGrant cross-namespace
authorization, weighted multi-backend materialization, zero-weight withdrawal,
mixed valid/invalid weighted blackhole legs, missing/unpermitted backend
fail-closed behavior, parent status (`Accepted`/`ResolvedRefs`/`Programmed` /
`UDPAmplificationProtection`), live backendRef and weight-only updates, deletion
withdrawal, and UDP amplification policy precedence/authorization/update/delete
— see [UDPRoute translation](#udproute-translation),
`tests/unit/gateway_core/k8s_udproute_translation_tests.rs`, and
`tests/unit/gateway_core/k8s_udp_amplification_policy_tests.rs`. CI
**Integration** Tests then run that translated config through the real UDP
runtime (`tests/integration/gateway_api_udproute_datapath_tests.rs`): the
translator's own listener port is bound by `start_udp_listener`, a client
datagram traverses the generated stream proxy and is answered by the backend the
route named, two `UDPRoute`s on two UDP listeners do not cross-talk, a weighted
`backendRefs` set is served from its generated upstream with per-session leg
stability, a leg naming an absent `Service` drops the datagram instead of
answering it, in-budget replies are forwarded, over-budget and cumulative
multi-datagram replies are dropped, and deleting the amplification policy
returns the listener to the finite default. The Gateway API conformance lab does **not** run a UDPRoute black-box step (Trusted Cross Build Policy freezes adding that executable automation), so the live evidence rides the required `Tests` aggregate instead. Upstream profile/features remain `GATEWAY-HTTP,GATEWAY-GRPC` / `Gateway,ReferenceGrant,HTTPRoute,GRPCRoute`; `GATEWAY-UDP` is **not** claimed on this pin. |
| `BackendTLSPolicy` | Not claimed by upstream conformance profiles | Watched and translated for Service-backed `HTTPRoute`/`GRPCRoute` backends: `validation.hostname` → upstream SNI, `caCertificateRefs` (ConfigMap inline PEM or Secret `k8s://…#ca.crt`) or `wellKnownCACertificates: System` (projected as the first-class `system://` trust source, which pins built-in webpki roots and never falls back to `FERRUM_TLS_CA_BUNDLE_PATH` or inherits `FERRUM_TLS_NO_VERIFY`), optional `subjectAltNames` → SAN allow-list, `backend_scheme: https`. Exactly one `targetRefs` entry is supported per the v1.5.1 implementation guidance; non-empty `spec.options` and malformed optional shapes are rejected. Invalid, conflicting, or partially-covering policies fail closed with an HTTP 500 fault abort — including a rule whose `backendRefs` mix policy-covered and uncovered Services, which Ferrum cannot represent in one upstream. Policy `status.ancestors` names the **targeted Service** as the single Ferrum ancestor (Ferrum's verdict takes no Gateway as input, so it cannot vary per Gateway) and carries `Accepted` / `ResolvedRefs` conditions; precedence losers report `Accepted=False, reason=Conflicted`. Ferrum's own contribution is therefore one entry regardless of how many Gateways route to the Service. `targetRefs[].sectionName` is resolved against the Service's actual `spec.ports[].name`: a `sectionName` that names no port makes the policy fail to attach and reports `Accepted=False, reason=TargetNotFound` with a field-specific message, and — because the intended port cannot be inferred — it neither applies to nor faults the Service's other, valid ports. Per GEP-1897, BackendTLSPolicy applies only to TCP traffic, and eligibility is decided on the port's **transport**: a port qualifies only when `spec.ports[].protocol` is proven `TCP` (omitted counts as TCP, matching the Kubernetes default; the comparison is case-insensitive). `UDP`, `SCTP`, and any unrecognized protocol value are all ineligible — GEP-1897 names UDP in its examples, but the rule it states is that the policy configures TLS for TCP traffic, and no TLS handshake can be originated on an SCTP or unknown-transport port. A policy that explicitly attaches to an ineligible port (a `sectionName` naming a `UDP`, `SCTP`, or unrecognized-protocol port) reports `Accepted=False, reason=Invalid` scoped to that port, leaving sibling TCP ports alone; a Service-wide policy on a Service with no TCP port at all is rejected the same way because it would govern nothing. Route traffic that actually selects a rejected policy fails closed with the HTTP 500 fault rather than originating TLS over a non-TCP transport or dropping to plaintext. A Service that mixes TCP and non-TCP ports is accepted with a warning carried in the `Accepted` condition message and the policy is effective only for the TCP ports; the non-TCP ports keep their pre-policy behaviour. Condition messages name the transport from a fixed set (`TCP` / `UDP` / `SCTP` / "not a recognized Kubernetes protocol") and never echo the raw cluster-supplied `protocol` string. A Service declaring more than 64 ports exceeds Ferrum's bounded port index, so the port transport cannot be proven and every policy targeting it is rejected fail closed. When third-party controllers have filled the CRD's 16-entry `ancestors` limit, Ferrum adds no entry (the spec forbids exceeding it), but translation is unaffected: the policy still applies and covered backends still originate TLS. `status.ancestors` is mutable state owned by other controllers, so letting it gate translation would let any controller with status-write access disable backend TLS origination and fault covered traffic. The consequence of a full ancestor map is therefore a reporting gap for that policy, never a traffic outage and never a drop to plaintext. |
| `ListenerSet` | Yes, via Ferrum unit/integration tests **and** a live black-box lab step (not an upstream feature claim) | Watched optionally (`gateway.networking.k8s.io/v1`, discovery skips when the CRD is absent) and bounded by the same configured source-namespace scope as Gateways and Routes. A `ListenerSet` attaches only when its `parentRef` selects a Ferrum-managed Gateway **and** that Gateway's `spec.allowedListeners.namespaces` permits the ListenerSet namespace (`Same` / `Selector` / `All`; default `None` → `Accepted=False` / `NotAllowed`). Accepted listeners merge into the parent Gateway's programming with precedence Gateway → oldest ListenerSet → `{namespace}/{name}`; hostname/protocol collisions on the same port mark the loser `Conflicted=True` (`HostnameConflict` / `ProtocolConflict`) and never materialize traffic. Routes parentRef the ListenerSet (optionally selecting a listener by `sectionName` or `port`) and reuse the same HTTP/L4 translation engine as Gateway listeners. A cross-namespace ListenerSet remains namespaced to its own resource for identity, route attachment, status, and Secret/ReferenceGrant resolution, while its physical frontend-TLS claim joins the attached Gateway namespace's serving plan. It retains its complete admitted listener-owned certificate set, but cannot mint a process-global default certificate from a namespace with no managed Gateway or make a disjoint-hostname parent listener conflicted merely by naming a different credential. Cross-namespace `certificateRefs` require a ReferenceGrant `from.kind=ListenerSet` (Gateway grants are not inherited). Status emits ListenerSet `Accepted`/`Programmed` plus per-listener conditions, and Gateway `status.attachedListenerSets` counts successfully attached sets. Update/delete withdraws mesh listeners and routes. Upstream profile/features remain `GATEWAY-HTTP,GATEWAY-GRPC` / `Gateway,ReferenceGrant,HTTPRoute,GRPCRoute` — `ListenerSet` is **not** advertised as a supported upstream feature on this pin. Evidence: `tests/unit/gateway_core/k8s_listenerset_translation_tests.rs`, `tests/integration/gateway_api_listenerset_tests.rs`, and `scripts/gateway_api_listenerset_conformance.sh`. |
| `GRPCRoute` | Yes, via upstream `GATEWAY-GRPC` | Watched and translated — see [GRPCRoute predicate translation](#grpcroute-predicate-translation). CI advertises `GRPCRoute` and runs the pinned upstream `GATEWAY-GRPC` core suite (exact method, header, listener hostname, weight, and core status) against a live Ferrum listener. Extended `GRPCRouteNamedRouteRule` is **not** claimed. Native gRPC route misses and `reject_unmatched` refusals map HTTP 404 → gRPC `UNIMPLEMENTED` (official HTTP↔gRPC table / Gateway API `GRPCExactMethodMatching`). |
| `TCPRoute` | Yes, via Ferrum black-box live checks (not upstream `GATEWAY-TCP`) | Lab installs the pinned `v1.5.1` experimental-channel CRD bundle (one coherent channel that includes `TCPRoute`/`TLSRoute`). Live kind traffic proves parent/listener attachment, same-namespace and AllowedRoutes cross-namespace parentRefs, same-namespace and ReferenceGrant cross-namespace backend resolution, tagged TCP echo forwarding, empty/missing/unpermitted backend fail-closed behavior, parent status (`Accepted`/`ResolvedRefs`/`Programmed`), live backendRef updates, AllowedRoutes tighten withdrawal, and deletion withdrawal. A present but non-Gateway parentRef opens no listener; only a genuinely parentless legacy input may use the backend-port fallback. Upstream profiles/features remain `GATEWAY-HTTP,GATEWAY-GRPC` / `Gateway,ReferenceGrant,HTTPRoute,GRPCRoute`; `GATEWAY-TCP` is **not** claimed on this pin (the profile/tests land in later Gateway API releases). |
| `TLSRoute` | Yes, via Ferrum black-box live checks (not upstream `GATEWAY-TLS`) | Watched at `gateway.networking.k8s.io/v1` and `v1alpha2`. On the pinned Gateway API v1.5.1 CRDs, `standard-install.yaml` serves `v1` only (`v1alpha2`/`v1alpha3` are present with `served: false`); `experimental-install.yaml` serves `v1`, `v1alpha2`, and `v1alpha3`. Ferrum dual-watches `v1` (storage) and `v1alpha2` (experimental / older installs); an unserved version is skipped at discovery, and objects that appear under both served versions are de-duplicated by `(group, kind, namespace, name)` in the reflector snapshot — the same mechanism as HTTPRoute `v1`/`v1beta1`. Ferrum does not watch `v1alpha3`. Live kind traffic proves AllowedRoutes cross-namespace parentRefs plus TLS Passthrough SNI selection (distinct hostnames on one listener → distinct backends; unmatched SNI fails closed), tagged TLS echo forwarding through encrypted passthrough, same-namespace and ReferenceGrant cross-namespace backend resolution, empty/missing/unpermitted backend fail-closed behavior, parent status (`Accepted`/`ResolvedRefs`/`Programmed`) and listener `attachedRoutes`, live backendRef updates, and deletion withdrawal. Translator materializes `passthrough: true` stream proxies (`BackendScheme::Tcp`) keyed by route `hostnames` on Gateway `protocol: TLS` / `tls.mode: Passthrough` listener ports. A present but non-Gateway parentRef opens no listener; only a genuinely parentless legacy input may use the backend-port fallback. The separate `TLSRouteModeTerminate` feature is not implemented or advertised: non-Passthrough TLS listeners are rejected with `Accepted=False` / `UnsupportedProtocol` and never fall back to a backend-port listener. Upstream profiles/features remain `GATEWAY-HTTP,GATEWAY-GRPC` / `Gateway,ReferenceGrant,HTTPRoute,GRPCRoute`; `GATEWAY-TLS` is **not** claimed on this pin. |
| `BackendLBPolicy` / `XBackendTrafficPolicy` session persistence | Partial (Ferrum black-box / translation; not an upstream conformance feature claim) | On the pinned `v1.5.1` experimental channel `BackendLBPolicy` was **removed** and replaced by `XBackendTrafficPolicy` (`gateway.networking.x-k8s.io`). Ferrum watches both shapes: historical `BackendLBPolicy` (`gateway.networking.k8s.io/v1alpha2`) when that CRD is still installed, and `XBackendTrafficPolicy` on the current pin. Representable Cookie `sessionPersistence` projects onto generated route Upstreams as `consistent_hashing` + `hash_on: cookie:…`, forcing Upstream materialization even for single-backend rules so sticky `Set-Cookie` injection runs on the live LB path. Persistence is **backend-bound**, as GEP-1619 requires: the cookie carries an HMAC-authenticated opaque token derived from the namespace-qualified route-scoped upstream identity and the full identity of the target that served the initial response (dial `host:port`, declared Service port / per-port policy lane, tags, locality, and path override — so a traffic split whose `backendRefs` resolve to the same endpoint through different Services or Service ports keeps separate bindings), and a returning request resolves that token through a per-upstream binding index materialized at config reload, returning the client to that exact endpoint (H1/H2, gRPC, WebSocket, and H3/cross-protocol dispatch alike). The process-local authentication key prevents clients from forging tokens from predictable route and endpoint metadata; tokens survive config reload, while a restart or another replica treats them as stale and transparently re-pins the client. The token discloses no backend address, credential, or secret and is never logged. Because the upstream is route-scoped, a token cannot steer traffic across routes, Services, namespaces, or policies. A token that is malformed, oversized, foreign, stale after endpoint removal, outside the selected subset/port lane, or unhealthy is treated as no session: the request re-selects normally and is issued a fresh binding, never bypassing health, subset, port, TLS, authorization, retry, or connection-limit semantics. A retry that legitimately rotates away from a failed endpoint issues the cookie for the endpoint that actually produced the successful response, on every retry-capable dispatch path (H1/H2, direct gRPC, WebSocket including H2 extended CONNECT, native H3, the H3 cross-protocol bridges, and H3 WebSocket); a gateway-synthesized rejection that dialed no backend issues no cookie. A resolved binding is additionally re-validated against the selected target's own per-port policy lane: if that lane is not consistent hashing on the same cookie, the binding fails closed to ordinary selection and reissue. The wire cookie name is deterministically scoped to the route resource and rule (the configured `sessionName` remains its readable prefix), preventing two route rules from sharing one session; that scope hashes the route's served `apiVersion`, and because the reconcile snapshot now always keeps the GA alias of a route watched under several versions, a deployment where a compatibility alias used to win sees a one-time cookie-name change on upgrade, after which the name is stable. Route-rule `sessionPersistence` overrides a Service-targeted policy. For a traffic split where only some Services carry a policy, Ferrum applies the selected persistence configuration to all backends in that rule, one of the behaviors explicitly permitted by GEP-1619; conflicting policy configurations fail closed. `cookieConfig.lifetimeType: Session` emits a browser session cookie (no `Max-Age`) only when `absoluteTimeout` is absent; `Permanent` requires `absoluteTimeout` → `Max-Age`. `idleTimeout`, Session+`absoluteTimeout` (Ferrum cannot enforce an internal absolute lifetime), Header persistence (Ferrum does not synthesize a response token), non-Service `targetRefs`, and `retryConstraint` fail closed with field-specific diagnostics — a policy carrying `retryConstraint` is rejected entirely (`Accepted=False` / `UnsupportedValue`) and no portion of it (including `sessionPersistence`) is applied. Multiple policies targeting the same Service use GEP-713 None-merge / oldest-wins precedence (creationTimestamp, then full resource identity); the winning policy stays `Accepted=True`, and every challenger that loses any Service target is `Accepted=False` / `Conflicted` (validation precedes conflict so an invalid object never becomes Accepted). That rejection is atomic in translation too: a policy that loses any one of its Services is withdrawn from every Service it targets, so only `Accepted=True` policies steer traffic. Policy `status.ancestors` reports `Accepted` / `UnsupportedValue` / `Conflicted`, preserves ancestor entries owned by other Gateway API implementations, and keeps `lastTransitionTime` stable while a condition's value is unchanged. When third-party controllers have filled the shared 16-entry ancestor map, Ferrum adds no entry (the spec forbids exceeding it), but translation is unaffected: session persistence still reaches the data plane. `status.ancestors` is mutable state owned by other controllers, so letting it gate translation would let any controller with status-write access drop stickiness. The consequence of a full ancestor map is therefore a reporting gap for that policy, never a loss of persistence behavior. Upstream profile/features remain unchanged — this is not advertised as a Gateway API conformance claim. |

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
| Materialization | One Ferrum stream proxy per rule per attached listener port, `backend_scheme: udp`. Distinct Gateways or listeners that share that numeric port therefore share one physical proxy, and UDP amplification policy is fail-closed aggregated across the represented claims. With no valid attached Gateway listener, no proxy or generated upstream is created; backendRefs are still fully validated so suppression cannot bypass hostile-input or `ReferenceGrant` checks |
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
| Status | `status.parents[]` carries Ferrum-authored `Accepted`, `ResolvedRefs`, `Programmed`, `Conflicted`, and `UDPAmplificationProtection` (`FiniteDefault` / `FinitePolicy` / `ExplicitUnlimited` on a materialized parent, or `False` / `NotProgrammed` when that parent was not programmed, without echoing the numeric factor), written through the same read-modify-write path as every other route kind. A fully shadowed same-listener UDPRoute loser stays `Accepted=True` / reason `Accepted` (attached) and reports `Programmed=False` with conflict evidence plus `Conflicted=True`; it is not flipped to `Accepted=False` for losing traffic ownership |
| Update / delete | Reconciliation regenerates live stream listeners and upstreams from the full snapshot; a changed `backendRefs` or a weight-only change replaces the upstream's target set under the same deterministic id, a deleted `UDPRoute` withdraws both the listener and its upstream, and deleting a conflict winner lets a previously suppressed loser materialize on the next reconcile |

Datagram semantics come from the existing Ferrum UDP data path and are not
re-implemented for Gateway API: sessions are keyed by client address with an
idle timeout.

The response-amplification guard is **always** engaged for a generated `UDPRoute`
proxy. Ferrum projects a finite controller default of `8.0` onto every
materialized UDP listener. Operators override that default with the Ferrum
`UDPResponseAmplificationPolicy` CRD (`gateway.ferrum.io/v1alpha1`), using
GEP-713 Direct Policy Attachment:

1. UDPRoute `targetRefs` (highest)
2. Gateway + `sectionName` (one listener on that Gateway's own
   `spec.listeners`; a `ListenerSet`-contributed listener is never selected by
   `sectionName`, only by the Gateway-wide tier below)
3. Gateway (all UDP listeners on that Gateway)
4. `GatewayClass.spec.parametersRef` naming this CRD
5. Controller default `8.0`

Same attachment level is oldest-wins (`creationTimestamp`, then
`{namespace}/{name}`). A Direct policy that loses any named target is
`Conflicted` and occupies none of its targets, so a later eligible policy can
still govern a remaining target. `GatewayClass.parametersRef` ignores a
conflicted Direct policy. Cross-namespace `targetRefs` require a `ReferenceGrant`
from `gateway.ferrum.io`/`UDPResponseAmplificationPolicy` to `Gateway` or
`UDPRoute`. A missing, invalid, unauthorized, or deleted policy never programs
unlimited amplification — the next precedence level, ultimately the finite
default, applies. `mode: Unlimited` is accepted only together with
`acknowledgeUnsafeAmplification: true`. Factors must be finite, greater than
zero, and at most 1024; rejected values do not unprogram the route.

Ferrum materializes one physical UDP proxy per rule per attached listener port.
When one `UDPRoute` attaches to distinct Gateways or listeners sharing that
port, each surviving claim keeps the precedence above and the proxy fail-closed
aggregates them: a finite factor dominates Unlimited, the smallest finite factor
wins, and the proxy is unlimited only when every represented claim is explicitly
Unlimited. Listener and parentRef order cannot weaken that boundary.

Runtime accounting is **cumulative per admitted client request**. Several
backend replies that are each under `request_size × factor` still fail closed
once their sum exceeds the remaining budget. A zero-length response consumes
one unit of remaining budget (payload bytes are charged exactly when nonempty)
so packet count stays finite under a finite factor. The budget is stored on the
UDP session, so weighted multi-backend selection cannot reset or multiply it.
Idle cleanup and listener/route deletion tear the session map down with the
existing idle-timeout path; no extra maps keyed by client or route are added.

`UDPRoute.status.parents[].conditions` includes Ferrum
`UDPAmplificationProtection` with reasons `FiniteDefault`, `FinitePolicy`, or
`ExplicitUnlimited` only for a parent whose translator recorded that posture.
An unprogrammed parent — translation failure, unmatched listener, or any
parent that never materialized a proxy — reports `False` / `NotProgrammed`
with a fixed message and never inherits `FiniteDefault`. Condition messages
do not echo resource names, section names, numeric factors, or translator
errors. Shared-port sibling parents each receive the exact physical-proxy
protection after aggregation, so a materialized parent is never `NotProgrammed`
because another parentRef sorted first. When one parentRef materializes on
several UDP listeners (different ports), that parent reports the conservative
aggregate: `ExplicitUnlimited` if any listener is unlimited, `FinitePolicy` only
when every listener uses a finite policy, and `FiniteDefault` when at least one
uses the controller default.
Process-wide unlabeled counters
`ferrum_udp_amplification_responses_allowed_total`,
`ferrum_udp_amplification_responses_dropped_total`,
`ferrum_udp_amplification_policy_invalid_total`, and
`ferrum_udp_amplification_unlimited_total` never carry route, backend, source,
factor, or error-text labels.

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
  accept-loop task is awaited before the replacement binds, so extra
  accept workers sharing the exclusive listen socket never overlap a
  plaintext generation with a TLS replacement. Already accepted connections keep draining.
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

## Rule-filter admission

Every rule in an `HTTPRoute` / `GRPCRoute` is validated before any route
configuration is emitted, so a supported rule never makes an unsupported
sibling look programmed. Beyond the per-filter field inventory, the shapes
below are refused rather than partially honored.

The status reason follows **what** is wrong, never which CRD mechanism
(`Pattern`, a required field, or an `XValidation` CEL rule) forbids it. A file-
or CP-delivered object never passed through the API server, so Ferrum re-checks
every one of these itself.

- **`IncompatibleFilters`** — the rule's filter *set* cannot be honored as
  declared: filters that conflict with each other, a filter type the route kind
  does not carry, or a filter type or field Ferrum does not implement. This is
  upstream's own definition of the reason, whose documented example is
  `URLRewrite` + `RequestRedirect` — a combination the CRD also forbids with CEL.
- **`Invalid`** — a bad *value* inside one filter: malformed, missing where
  required, or inconsistent with the rest of that filter or its rule.
- **`UnsupportedValue`** — a CRD-valid value Ferrum declines to implement or
  refuses by policy.

| Shape | Status | Why |
|---|---|---|
| `URLRewrite` + `RequestRedirect` in one rule | `Accepted=False` / `IncompatibleFilters` | A redirect answers the request itself, so the rewrite could never be applied. Honoring one would silently drop the other. |
| A repeated `RequestHeaderModifier`, `ResponseHeaderModifier`, `RequestRedirect` or `URLRewrite` in one rule | `Accepted=False` / `IncompatibleFilters` | Upstream declares these at most once per rule; a repeat is a conflicting declaration, and taking the first would discard the second. |
| `URLRewrite` on a `GRPCRoute` | `Accepted=False` / `IncompatibleFilters` | Upstream's GRPCRoute filter enum carries no `URLRewrite`. |
| An unknown field inside `URLRewrite.path` (for example `replaceQuery`) | `Accepted=False` / `IncompatibleFilters` | A filter field Ferrum does not implement, exactly like an unhandled field elsewhere in a filter. |
| `URLRewrite` `path.type: ReplacePrefixMatch` with a non-`PathPrefix` match in the rule | `Accepted=False` / `Invalid` | There is no matched prefix to rebase. Upstream is stricter (exactly one `PathPrefix` match); Ferrum also accepts several `PathPrefix` matches and a match-less rule, each rebased against its own prefix. |
| `URLRewrite.path` carrying the modifier field of the other `type` (`type: ReplaceFullPath` with `replacePrefixMatch`, or the reverse) | `Accepted=False` / `Invalid` | Only the selected type's field is honored, so the other replacement would be silently dropped. |
| An unknown `URLRewrite` `path.type` | `Accepted=False` / `UnsupportedValue` | A newer channel may add an enum member Ferrum has not implemented yet. |
| `ResponseHeaderModifier` naming a hop-by-hop or framing response field | `Accepted=False` / `UnsupportedValue` | Ferrum strips those from backend responses by design; reintroducing one from a route filter would punch a hole in the proxy boundary. |
| `ResponseHeaderModifier` `set` / `add` / `remove` of `grpc-status`, `grpc-message` or `grpc-status-details-bin` (any case, either route kind) | `Accepted=False` / `UnsupportedValue` | A Trailers-Only gRPC response — how servers report most errors — carries its terminal status in the one HEADERS frame the filter edits, so the filter could turn a failed RPC into `grpc-status: 0` or strip its outcome. HTTPRoute is covered too because it can carry gRPC traffic. |
| A malformed header name/value, rewrite hostname, or replacement path | `Accepted=False` / `Invalid` | The generated dispatch plugin applies the same gates, so admitting it would leave an "Accepted" route carrying configuration no data plane can load. |

### `URLRewrite` prefix rewriting

`ReplacePrefixMatch` reproduces the upstream `HTTPPathModifier` table. Upstream
prefix matching is path-element aware, so `/foo/` and `/foo` select the same
requests and must rewrite identically; Ferrum's dispatch plugin strips a literal
byte prefix, so the translator canonicalizes the matched prefix by dropping a
trailing separator and reducing the root `PathPrefix: /` to the empty prefix
(strip nothing, prepend). An empty `replacePrefixMatch` normalizes to `/`.
A `PathPrefix` match with no `value`, and a match with no (or a null) `path`,
rebase against `/` — upstream's default, and where routing already places such
an entry. The same prefix resolution applies to `RequestRedirect`
`ReplacePrefixMatch`.

| Request path | Prefix match | Replacement | Forwarded path |
|---|---|---|---|
| `/foo/bar` | `/foo` | `/xyz` | `/xyz/bar` |
| `/foo/bar` | `/foo/` | `/xyz` | `/xyz/bar` |
| `/foo/bar` | `/foo` | `/xyz/` | `/xyz/bar` |
| `/foo` | `/foo` | `/xyz` | `/xyz` |
| `/foo/` | `/foo` | `/xyz` | `/xyz/` |
| `/foo/bar` | `/foo` | *(empty)* or `/` | `/bar` |
| `/foo` | `/foo` | *(empty)* or `/` | `/` |
| `/bar` | `/` | `/xyz` | `/xyz/bar` |

The query string is carried separately and is never rewritten. Gateway API
proxies are generated with `strip_listen_path: false` and no backend path
prefix, so the rewrite is the only path mutation on the request — a path is
never stripped and replaced twice. `hostname` rebases the forwarded
`Host` / `:authority` only: it does not change backend selection, upstream SNI,
or `BackendTLSPolicy` verification.

### `ResponseHeaderModifier` and response trailers

The translator projects the filter onto route-local response-transform rules
carried by the rule's dispatch entry, and auto-emits a rules-free
`response_transformer` on that proxy to consume them. That consumer is additive
to a same-name **global** `response_transformer` (issue #4304): global static
rules run first and the matched route's rules run last, so a route `set` wins a
name the global also writes, while unrelated global rules keep applying.

A response-header policy governs the response **trailers** of the requests it
applies to, because a route override can name any field at request time and a
field the backend sent only as a trailer would otherwise slip past it. The
gateway's response-trailer governance therefore drops the non-reserved backend
trailers of every request a filtered rule matches — this is a suppression, not a
modification: `ResponseHeaderModifier` never rewrites a trailer.

That cost is **per request, not per proxy**. The generated consumer carries no
rules of its own, so it declares a request-conditional trailer policy
(`RequestConditionalUnbounded`): the fail-closed drop applies only when the
matched dispatch rule published a response transform for that request. This
matters because same-kind routes that share a hostname, listener and path merge
onto one proxy with one consumer — two GRPCRoutes whose method-only,
header-only or match-less rules all land on `/`, or two HTTPRoutes on one
`PathPrefix` where one rule is header-gated. A sibling there, possibly another
team's route, keeps its application trailers.

For a native gRPC call the practical contract is:

- **Preserved**: the response message and streaming, and the terminal
  `grpc-status` / `grpc-message` / `grpc-status-details-bin` fields.
- **Modified**: the response's initial metadata (the HEADERS frame), which is
  what upstream defines the filter to act on.
- **Dropped**: other application trailers of the requests that rule matches.

A sibling rule — on the same route, or on another route merged onto the same
proxy — that declares no response-header filter keeps its application trailers,
so the cost is scoped to the rules that opt in. Operators who need application
trailers on a gRPC route should not attach a `ResponseHeaderModifier` to that
rule. An operator-authored `response_transformer` with its own static rules is
different: it governs every response on its proxy, as it always has.

The filter may not name the terminal fields themselves: a response-side `set`,
`add` or `remove` of `grpc-status`, `grpc-message` or `grpc-status-details-bin`
is refused with `UnsupportedValue` (see the table above).

## Rule timeouts

`HTTPRoute.rules[].timeouts` is a standard-channel field on the pinned `v1.5.1`
CRDs. GRPCRoute defines no such field, so a GRPCRoute rule carrying one keeps the
`UnsupportedValue` refusal, as does `rules[].retry` (experimental channel) on
either kind — retry translation is a separate follow-up.

**Admission.** Both values are Gateway API durations (GEP-2257), checked against
the CRD pattern `^([0-9]{1,5}(h|m|s|ms)){1,4}$` and summed the way Go's
`time.ParseDuration` sums them (`1s1s` is two seconds). The CRD's CEL rule is
re-checked too: when both are set and `request` is not the zero duration,
`backendRequest` may not exceed it. A value outside the grammar, a non-string
value, a non-object `timeouts`, and a CEL violation are `Accepted=False` /
`Invalid`; a `timeouts` sub-field the CRD does not define is
`UnsupportedValue`. No diagnostic echoes the offending value.

**Projection.** Each rule's `timeouts` land on that rule's own
`mesh_route_dispatch` entry: `request` as `request_timeout_ms`, `backendRequest`
as `timeout_ms` (or `timeout_disabled: true` for `0s`). A path-only rule that
carries `timeouts` still emits its own dispatch entry, so the policy applies to
exactly the requests the rule matches. Nothing is written onto the generated
proxy or upstream, so a sibling rule — on the same route, or on another route
merged onto the same proxy — keeps the proxy defaults (a 30 s per-attempt read
bound and no total deadline). A rule with `timeouts` but no `backendRefs` and no
`RequestRedirect` answers HTTP 500, like a filter-only rule. Removing `timeouts`
withdraws the policy on the next reconcile.

**`backendRequest`** bounds one backend attempt: the wait for its response head
and the idle gap between response frames. Expiry is the ordinary backend-timeout
`504` (`{"error":"Backend timeout"}`). `0s` explicitly clears the proxy's default
bound for the rule. **Known deviation:** upstream v1.5.1 defines
`backendRequest` as running from when the request starts being sent to the
backend until the full response has been received, per attempt. Ferrum does not
bound an attempt's total duration: a backend that trickles its body inside the
idle gap is not cut per attempt. `request` still cuts it, but a rule with
`request` unset or `0s` leaves such an attempt without any total bound. The
upstream `HTTPRouteTimeoutBackendRequest` test delays only the response head,
which Ferrum does bound.

**`request`** is one absolute deadline, anchored to the instant the request was
received and armed once the rule is selected, so request-phase time counts
against it and no retry re-arms it:

| Request | Expiry before the response head | Expiry while the body streams |
|---|---|---|
| HTTP/1.1 or HTTP/2, not gRPC | The in-flight attempt or retry backoff is cancelled — and no new attempt starts once the budget is spent — and the client gets `504` `{"error":"Request timeout"}` with `X-Gateway-Error: backend_timeout`. Never retried. The transaction log names the phase in metadata `route_request_timeout`: `dispatch` when the backend held the cancelled attempt (error class `read_write_timeout`, charged to that backend), `before_dispatch` when the attempt had not yet been handed to a backend, and `retry_backoff` (both the health-neutral `dispatch_policy_rejected`) | The body ends with a timeout error: the HTTP/2 stream is reset and the HTTP/1.1 connection is closed rather than presenting a complete response; a backend `Content-Length` stays advertised, so the cut reads as a short body. `body_error_class` is `read_write_timeout`, and the cut is not charged to the backend |
| gRPC / gRPC-Web, any frontend | Folded into the RPC deadline (the earlier of the route budget and any client `grpc-timeout` / `grpc_deadline` budget wins), so the existing deadline machinery answers `DEADLINE_EXCEEDED` and forwards the remaining budget upstream as `grpc-timeout` | `DEADLINE_EXCEEDED` trailers before response DATA, a stream reset after it |
| HTTP/3, not gRPC | Refused with `503` `{"error":"Route request timeout is not supported over HTTP/3"}` before target selection, breaker admission, or any dial | — |

**Backend-health attribution.** A `request` expiry is charged to a backend —
circuit breaker, passive health (Istio outlier detection included), and the
latency samples — only when that backend held the request. An attempt is handed
to the backend once the gateway has finished every gateway- and client-side step
(collecting a buffered client body, request-body hooks, DNS, backend admission)
and begun the dial, stream open, or send. Retry attempts are handed over from
their start, since the retry planner admits them first and replays the already
buffered body. So a client that stalls its upload while the gateway is buffering
it — retries force that buffering — cannot open a healthy backend's breaker, and
a backend that holds a request past the deadline without answering is charged.
A streaming (unbuffered) upload travels with the backend exchange, so a stall
after the handoff is attributed like the per-attempt header wait already is. A
cut after the response head is never charged: the backend answered, and the
total budget ends a long healthy download or a slow-reading client as surely as
a slow backend. A gRPC request keeps the attribution of the client RPC deadline
it was folded into.

The HTTP/3 refusal is deliberate and fail-closed. The native HTTP/3 relays write
the response head and body from inside the dispatch, so they cannot yet turn the
deadline into a `504` or a mid-body reset; serving the request would drop the
policy it was routed under. HTTP/3 is only reachable on TLS listeners with
`FERRUM_ENABLE_HTTP3=true`, and the same request over HTTP/1.1 or HTTP/2 is
bounded as above. **The gateway never steers a client onto the refusal:** a
browser caches `Alt-Svc` for the whole origin (`ma=86400`) and does not fall back
to TCP on an HTTP `503`, so the H1/H2 frontends omit `Alt-Svc` from every
response on a listener port that serves a rule carrying `request` — on every
port when that rule is on a port-agnostic route. Withholding it on the timed
rule's own responses alone would not be enough, because any sibling route's
response on the same origin would still advertise HTTP/3. A client that cached
`Alt-Svc` before the rule gained its deadline, or reaches HTTP/3 without it (a
DNS `HTTPS` record or explicit client configuration), still gets the `503` until
it falls back on its own. On HTTP/3 the refusal also runs before the deferred
`before_proxy` pass, so a `response_mock` or `fault_injection` abort that defers
behind a backend-path policy plugin answers `503` there rather than the mock or
abort H1/H2 return. Upgraded WebSocket and CONNECT-UDP tunnels are not HTTP
response bodies and are not bounded by `request` on any frontend. Gateway-local
plugin hooks on a non-gRPC request are not cancelled mid-hook; their time counts
against the budget, which is enforced when each backend attempt starts, while it
is awaited, in retry backoff, and while the body streams (the plugins the
translator generates make no outbound calls). A client that stops reading a
streamed response is cut when the transport next polls the body.

The upstream `HTTPRouteTimeoutRequest` and `HTTPRouteTimeoutBackendRequest`
tests exercise the HTTP/1.1 path. Ferrum's own data-plane regressions in
`tests/integration/k8s_controller_gateway_status_tests.rs`
(`gateway_route_timeouts_reach_the_data_plane`,
`gateway_route_request_timeout_spans_retry_attempts_and_backoff`,
`gateway_route_request_timeout_ends_grpc_calls_with_deadline_exceeded`,
`removing_rule_timeouts_withdraws_the_deadline`,
`gateway_route_request_timeout_does_not_charge_a_stalled_upload_to_the_backend`,
`gateway_route_request_timeout_charges_a_backend_that_stalls_response_headers`,
`gateway_route_request_timeout_body_cut_is_not_charged_to_the_backend`) cover
the pre-head `504`, the mid-body cut, the per-attempt bound inside a larger
total budget, one budget across retry attempts and backoff with its
`retry_backoff` transaction-log phase (with an operator-configured proxy retry,
since Gateway API `retry` is not translated yet), the gRPC fold, `0s`, sibling
isolation, withdrawal, and backend-health attribution through a live circuit
breaker. The paused-clock unit tests in
`tests/unit/gateway_core/route_request_deadline_tests.rs` pin the attempt
wrapper (a spent budget refuses an attempt without polling it), the attribution
rule, `Content-Length` preservation, and `Alt-Svc` withholding.

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
- **Filter-only rule with no backendRefs.** An HTTPRoute rule with no
  `backendRefs` and no `RequestRedirect`, whose only filters are header
  modifiers and/or `URLRewrite`, forwards nowhere, so upstream requires a 500.
  Ferrum attaches the same 100% fault-abort (`NoServiceableBackend`) rather than
  forwarding to an unresolvable backend. A GRPCRoute rule in that shape keeps
  the blackhole backend, exactly as its all-zero-weight rule does. The
  translator test `http_route_filter_only_rule_without_backend_refs_answers_500`
  pins the fault, and
  `gateway_response_header_modifier_reaches_the_client_through_the_data_plane`
  asserts the `500` through the gateway.
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
- The upstream Gateway API conformance suite pinned by `GATEWAY_API_VERSION`, defaulting to `v1.5.1`, running the complete `GATEWAY-HTTP` and `GATEWAY-GRPC` profiles with explicit supported features `Gateway,ReferenceGrant,HTTPRoute,GRPCRoute` plus the Extended features Ferrum implements end to end — the filter features `HTTPRouteResponseHeaderModification`, `HTTPRoutePathRewrite` and `HTTPRouteHostRewrite`, and the rule-timeout features `HTTPRouteRequestTimeout` and `HTTPRouteBackendTimeout` (issue #5646) — which makes the suite RUN their tests rather than skip them. TCPRoute/TLSRoute remain gated by Ferrum black-box evidence, not by advertising upstream `GATEWAY-TCP` / `GATEWAY-TLS` profiles on this pin.

Direct black-box checks cover hostname, path, method, headers, weighted backend selection, zero-weight-only HTTP 500 behavior, cross-namespace references, invalid references, backend failure, TLS, route updates, and route deletion for HTTP, plus TCPRoute parent/listener attachment, AllowedRoutes cross-namespace parentRefs (attach + tighten withdrawal), ReferenceGrant backend resolution, tagged echo traffic, fail-closed empty/missing/unpermitted backends, status, update, and deletion, plus TLSRoute AllowedRoutes cross-namespace parentRefs, Passthrough SNI selection, ReferenceGrant backend resolution, tagged TLS echo traffic, unmatched-SNI and empty/missing/unpermitted backend fail-closed behavior, status, update, and deletion, plus ListenerSet allowedListeners attachment, HTTPRoute parentRef traffic, NotAllowed default, Gateway `attachedListenerSets`, and delete withdrawal, plus GatewayClass observed-authority create/delete: a dedicated listener appears when the owned `GatewayClass` is created and withdraws without restarting Ferrum when that class is deleted. The pinned upstream suite owns live GRPCRoute conformance evidence. Diagnostics and the upstream conformance report are uploaded from `conformance-results/` as retained CI artifacts.

Lab bootstrap uses `scripts/gateway_api_conformance_lab_setup.sh` (kind ports, experimental CRDs, TCP/TLS listener Service ports). The experimental CRD bundle is downloaded to a file with bounded retries and backoff and verified against a SHA-256 pinned next to `GATEWAY_API_VERSION` in that script before `kubectl apply`, so a transient gateway-api release CDN 5xx retries instead of failing this required gate, and a mismatched bundle fails closed. The version and the digest move together (recompute with `curl -fsSL <experimental-install.yaml URL> | shasum -a 256`); a dispatch run pinning a different tag must pass the matching `GATEWAY_API_EXPERIMENTAL_SHA256`. HTTP/GRPC upstream and black-box phases stay in `scripts/gateway_api_data_plane_conformance.sh`; TCPRoute, TLSRoute, ListenerSet, and GatewayClass-authority black-box and supplemental diagnostics run via `scripts/gateway_api_tcproute_conformance.sh`, `scripts/gateway_api_tlsroute_conformance.sh`, `scripts/gateway_api_listenerset_conformance.sh`, and `scripts/gateway_api_gatewayclass_authority_conformance.sh` so the Trusted Cross Build Policy frozen `gateway_api_data_plane_conformance.sh` surface on `main` stays untouched. `UDPRoute` evidence stays in the required `Tests` aggregate — translation/status/lifecycle in the Unit Tests job (`tests/unit/gateway_core/k8s_udproute_translation_tests.rs`) and the live UDP data path in the `protocols-data-plane` integration shard (`tests/integration/gateway_api_udproute_datapath_tests.rs`); this workflow does not add UDPRoute executable automation under the Trusted Cross Build Policy.

The GatewayClass authority phase requires `GATEWAY_API_LAB_CONTEXT=kind-ferrum-gwapi` and an absolute `GATEWAY_API_LAB_OWNERSHIP_FILE` path shared with lab setup. For a local lab, export both before running setup, then keep the same values when running `scripts/gateway_api_gatewayclass_authority_conformance.sh blackbox` (and its `diagnostics` mode). For example, use `GATEWAY_API_LAB_OWNERSHIP_FILE="${TMPDIR:-/tmp}/gateway-api-gatewayclass-ownership-$$.tsv"` for a fresh run. Setup validates the context identity first, then pins every kubectl and Helm invocation to that context, so its CRD, namespace, secret, and control/data-plane writes cannot land on an ambient context that points at another cluster. Setup creates the class with a random run annotation and records its UID in that file. The authority phase checks the explicit Kind context, its control-plane node, the annotation, and the UID; deletion sends the UID as a Kubernetes delete precondition. An existing class or stale ownership record causes the run to stop rather than overwrite it. The hosted workflow sets these variables for the whole lab job.

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
reconciles after upgrades or legacy merge-patch writes. Every SSA status write
also copies the freshly read object's non-empty `metadata.resourceVersion` into
the apply document as a compare-and-swap precondition: dropping a timed-out
client future does not cancel the API server's work, and without that token a
later-arriving apply from the same forced field manager could overwrite a newer
reconcile. A live status read that fails or has no `resourceVersion` refuses the
write so the status-plan cursor stays unchanged.

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

### Local listener realization is not fed back into Gateway status

`Programmed` reports **translation and materialization** — that Ferrum accepted
the Gateway, produced listeners, and (optionally) that the serving data-plane
Service has a ready endpoint. It deliberately does not report whether a
particular Ferrum process actually bound the socket for a listener port.

That gap is structural, not an oversight. The Gateway API status writer runs
only in **control-plane mode** (`k8s_controller::start_k8s_controller`, launched
from `modes/control_plane.rs`), and control-plane mode binds no proxy listeners
at all. The dynamic listener sockets are bound by the *data plane* — `file`,
`database`, and `dp` modes, through
`proxy::gateway_listener::GatewayListenerManager`. The CP↔DP gRPC plane
(`proto/ferrum.proto`) carries configuration from CP to DP only:
`SubscribeRequest` / `FullConfigRequest` advertise a node id, version,
namespace, real-IP header, and heartbeat capability, and there is no DP→CP
status, realization, or health report message. There is therefore no existing
production path by which a DP's local bind outcome could reach a Gateway status
patch, and inventing one — writing Gateway listener conditions from a process
that never observed the socket, or synthesizing a DP report the wire protocol
does not carry — would make `Programmed` less trustworthy than it is today.

Local realization is instead reported where the process that owns the socket can
report it honestly (issue #3810):

* authenticated `/health` → `gateway_listeners` (affected ports, `tcp`/`quic`
  half, closed-set reason, admission-vs-runtime origin, config generation,
  sanitized detail, retry count), described in
  [admin_api.md](admin_api.md);
* the fixed-cardinality `ferrum_gateway_listener_*` Prometheus families,
  described in
  [prometheus_metrics.md](prometheus_metrics.md#dynamic-gateway-api-listener-realization);
* `status: "degraded"` on `/health` for unauthenticated probes, and optional
  readiness degradation via
  `FERRUM_GATEWAY_LISTENER_FAILURE_FAILS_READINESS`.

Closing the gap in Gateway status proper requires a new DP→CP realization report
on the ConfigSync plane; that is a protocol change and is deliberately out of
scope here.

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

A failing run additionally uploads
`gateway-api-conformance-failure-evidence-<version>`, written by
`scripts/gateway_api_data_plane_conformance.sh failure-evidence`: controller
logs, a compact HTTPRoute parent-status digest, cluster objects, node/pod
resource pressure, the `ferrum_k8s_controller_*` metric families, and
`status-budget-warnings.txt`. That last file is also echoed into the job log.

### Diagnosing a 60-second parent-status timeout

The suite fails whichever test is running when a route does not receive parent
status within its fixed 60s wait, so the failing test name is not the signal —
the timing is. Two causes look identical in the suite output:

- **A stalled status write blocking the reconcile loop.** Status patch batches
  are awaited inline on the single reconcile loop, so one Kubernetes status
  request that hangs stops *every* object's status from being published. The
  fingerprint is a `Reconciliation complete` line whose `elapsed_ms` dwarfs its
  neighbours (which normally complete in tens of milliseconds), a
  `status-budget-warnings.txt` entry naming the object and phase, and a rise in
  `ferrum_k8s_controller_status_request_timeouts_total`. Ferrum bounds this at
  15s per batch (issue #4239), well below the suite's wait, so it should no
  longer be able to fail a test on its own.
- **A status plan racing object deletion.** A test can delete a Gateway or route
  after Ferrum plans its status write but before the API request arrives. The
  resulting 404 is terminal success for that status-only operation: no object
  remains to retry. Ferrum skips the stale write and lets the fairness cursor
  advance; retaining the cursor on that expected 404 would replay the same dead
  window and starve live status updates behind it.
- **A watch that stopped delivering.** The controller keeps reconciling with a
  frozen object set, so reconciles stay fast and the route never appears in any
  plan at all. Look for `ferrum_k8s_controller_watch_idle_relists_total`, for a
  `Relisted … store disagrees with the generation it replaced` warning — it
  names the objects the watch missed and advances
  `ferrum_k8s_controller_watch_relist_missed_deletes_total` /
  `_missed_adds_total`, which is the proof of a missed event — and for the
  `FERRUM_K8S_WATCH_IDLE_RELIST_SECS` recovery described in
  [`docs/mesh.md`](mesh.md). The lab sets that window to 20 s so a stale scope
  converges inside the black-box probe budget — but the TLSRoute delete check
  does not accept that repair as a pass: it fails when
  `ferrum_k8s_controller_watch_deletes_total` did not advance across the
  deletion (the withdrawal was repaired by a relist rather than observed) and
  emits a `::warning::` when `watch_relist_missed_deletes_total` advanced for
  some other object during the check. A scope the API server refuses with HTTP
  403 logs once at error level when the refusal is first seen (repeats stay at
  debug, recovery logs once at info) and is held two minutes between attempts;
  any other failed initial list is held for a doubling interval up to 30 s;
  `ferrum_k8s_controller_watch_errors_total` counts the attempts.

Reconcile latency under CPU contention is a third shape and shows up as *many*
slow reconciles plus node pressure in `top-nodes.txt` / `nodes.describe.txt`,
not one outlier. Do not respond to any of these by raising the suite's wait.

## In-process Istio + xDS suite

The second compatibility surface — Istio `networking.istio.io` /
`security.istio.io` CRDs plus the xDS type URLs Ferrum subscribes to — is
covered by the in-process `tests/conformance/` suite, documented under
[Istio + xDS Conformance Suite](../CONFORMANCE.md#istio--xds-conformance-suite)
in the repo-root conformance index.
