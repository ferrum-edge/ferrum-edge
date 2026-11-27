# Known Limitations

Behaviour that Ferrum Edge does not support today, stated in one place. Each
entry says what is not supported, what happens instead, what to do about it, and
where the detail lives. An entry with an issue link is open product work; an
entry marked **Not planned** is a deliberate non-goal. Removing an entry from this
page means the behaviour shipped, and the release notes say so.

Feature maturity (GA, Beta, Experimental, Dev-only) and what each level promises
are defined in [support_policy.md](support_policy.md#feature-maturity-levels).
The mesh product contract, including every open mesh deferral, is
[mesh_supported_matrix.md](mesh_supported_matrix.md).

## Proxy protocols

| Limitation | What happens | What to do | Detail |
|---|---|---|---|
| WebSocket upgrade to a Unix-socket backend declared `http2` or `grpc` (h2c) | Refused with `502`: RFC 8441 Extended CONNECT over h2c is not implemented. The request is never downgraded or sent to the placeholder port. | Declare the socket `http` (HTTP/1.1) for WebSocket traffic, or serve WebSocket on a separate HTTP/1.1 socket. | [mesh.md → Unix-socket backends](mesh.md#unix-socket-backends) |
| DTLS passthrough: a later ClientHello on an already established 5-tuple | Not reclassified. The session stays on the proxy its first ClientHello selected. | Route by SNI on the first ClientHello only; clients that need a different backend open a new 5-tuple. | [tcp_udp_proxy.md → TLS/DTLS Passthrough Mode](tcp_udp_proxy.md#tlsdtls-passthrough-mode) |
| HTTP/3 gRPC-Web bridge: three request-side terminals written directly (the `413` for an oversized declared `Content-Length` on a streaming dispatch, the `413` for a streaming upload that overflows mid-body, and the `408` for an upload read timeout) | Not passed through the reject-path `after_proxy` decorators, so they carry no gateway CORS headers and a browser client may be unable to read the gRPC status. Buffered upload drain refusals and the bridge's other terminals are decorated. | Size client uploads below the route limit; serve browser gRPC-Web over HTTP/1.1 or HTTP/2 if the client must read these statuses. | [http3.md → Route request deadline](http3.md#route-request-deadline-request_timeout_ms-gateway-api-timeoutsrequest) |

## Plugins and notifications

| Limitation | What happens | What to do | Detail |
|---|---|---|---|
| `ai_stream_router` provider fallback | Not implemented: the plugin commits one provider per request, and a `fallback` block is refused at admission (`400`, validation error, or refused publication). | Use health checks, circuit breaking, and one proxy per provider for redundancy. | [ai_stream_router.md](plugins/ai_stream_router.md) |
| Native PagerDuty and Opsgenie notification channels | Not provided. Native channels are Slack, Microsoft Teams, Discord, the generic webhook, and email (SMTP). | Use the generic webhook channel with `body_template` and `headers`. | [notifications.md → Generic webhook](notifications.md#generic-webhook) |

## Kubernetes Gateway API

| Limitation | What happens | What to do | Detail |
|---|---|---|---|
| HTTPRoute / GRPCRoute filters `RequestMirror`, `CORS`, `ExternalAuth`, `ExtensionRef`, and `backendRefs[].filters` | Not implemented. The route is refused with `Accepted=False` / `IncompatibleFilters` and `Programmed=False`; other valid routes stay programmed. | Remove the filter, or use the equivalent Ferrum plugin (`request_mirror`, `cors`, an auth plugin) on a natively configured proxy. | [gateway_api_conformance.md → Rule-filter admission](gateway_api_conformance.md#rule-filter-admission), [CONFORMANCE.md](../CONFORMANCE.md) |
| GRPCRoute `timeouts` and `retry` | Refused with `Accepted=False` / `UnsupportedValue` (upstream does not define them for GRPCRoute). | Set timeouts and retries on the gRPC client, or on a natively configured proxy. | [CONFORMANCE.md](../CONFORMANCE.md) |
| `TLSRoute` Terminate mode (`TLSRouteModeTerminate`) | Not implemented. A non-Passthrough TLS listener is refused with `Accepted=False` / `UnsupportedProtocol`; it never falls back to a backend-port listener. | Use TLS Passthrough, or terminate TLS on an `HTTPS` listener with HTTPRoute. | [gateway_api_conformance.md → Supported-Feature Matrix](gateway_api_conformance.md#supported-feature-matrix) |

## Service mesh

| Limitation | What happens | What to do | Detail |
|---|---|---|---|
| ServiceWaypoint L7 routing | A ServiceWaypoint is an HBONE L4 relay for its bound Services with authorization scoped to each CONNECT destination's workload. It does not apply VirtualService `http[]` routes, does not terminate HTTP on `:15008`, and does not materialize Gateway API GAMMA HTTPRoutes with Service parents. Open: [#7500](https://github.com/ferrum-edge/ferrum-edge/issues/7500), [#7501](https://github.com/ferrum-edge/ferrum-edge/issues/7501). No live end-to-end suite yet: [#7503](https://github.com/ferrum-edge/ferrum-edge/issues/7503). | Apply `http[]` routes at the client Sidecar (Experimental) or bind the workloads to a NodeWaypoint (Experimental). | [mesh.md → Service Waypoint](mesh.md#service-waypoint) |
| VirtualService `http[]` destination in another namespace (Sidecar, NodeWaypoint) | The data plane refuses that carried route with a warning and serves the host through its plain Service route where one exists (a host no modeled Service owns has no such fallback: the VirtualService route is simply removed). The VirtualService stays `FerrumAccepted=True` (its gateway routes are unaffected) and counts them in its `FerrumAccepted` message and lists each in `status.ferrum.translation.deferred_fields` (an entry starting `http[].route[].destination` naming the route and leg, the host and the Service; at most 32 entries and 8 KiB, then one entry counting the rest). A zero-weight leg of a multi-destination route is listed as omitted during translation, since no data plane receives it. A fully qualified host (`<svc>.<ns>.svc.<domain>`) is read with the controller's `FERRUM_K8S_CLUSTER_DOMAIN`, the data planes classify it with their `FERRUM_MESH_CLUSTER_DOMAIN`; the two must match for the status to predict the refusal (the `<svc>.<ns>` and `<svc>.<ns>.svc` forms are reported either way). Open: [#7499](https://github.com/ferrum-edge/ferrum-edge/issues/7499). | Keep `http[]` destinations in the VirtualService's namespace. | [mesh.md → NodeWaypoint route carriage](mesh.md#mesh-data-planes-nodewaypoint-route-carriage) |
| VirtualService `http[]` routes on Sidecar | Experimental, and applied automatically with no opt-in: a Sidecar asks the control plane for them and applies every mesh-bound VirtualService's `http[]` routes it receives. Covered by deterministic integration tests and, since [#7502](https://github.com/ferrum-edge/ferrum-edge/issues/7502), by a release-blocking live gate in `mesh-e2e-sidecar` (a 90/10 weighted split within 85-95% and `x-canary` header-match dispatch on a captured Sidecar client, across two STRICT-mTLS destinations). Other `http[]` actions (rewrites, retries, timeouts, faults, mirrors, DestinationRule leg-by-leg dispatch) and cross-namespace destinations have no live gate. | Verify the `http[]` actions you rely on beyond weighted splits and header matches in your own environment; do not bind a VirtualService to the mesh if its `http[]` routes must not apply to Sidecar clients. | [mesh_supported_matrix.md → Current headline state](mesh_supported_matrix.md#current-headline-state) |
| `ServiceEntry.workloadSelector` | Translated and carried, but endpoints are not selected from the matching Pods or WorkloadEntries: the entry serves only its declared `endpoints[]`, and status lists the field in `deferred_fields`. | Declare `endpoints[]`, or use the Service the workloads back. | [mesh.md → Istio Compatibility Gaps](mesh.md#istio-compatibility-gaps) |
| `targetRef` / `targetRefs` on `PeerAuthentication`, `RequestAuthentication`, `Telemetry`, and `ProxyConfig` | Rejected; never widened into selector, namespace, or mesh-wide scope. Target references are supported on `AuthorizationPolicy` only. | Use `selector` (or namespace scope) on those kinds. | [mesh.md → AuthorizationPolicy targetRefs](mesh.md#authorizationpolicy-targetref--targetrefs-issue-3226) |
| DestinationRule `outlierDetection.consecutiveGatewayErrors`, `consecutiveLocalOriginFailures`, `minHealthPercent` | Parsed past with a warning and listed in `deferred_fields`. Ferrum keeps one failure bucket and bounds ejection with `maxEjectionPercent` alone. | Use `consecutive5xxErrors` and `maxEjectionPercent`. | [mesh.md → DestinationRule limitations](mesh.md#destinationrule-limitations--approximations--deferred-fields) |
| VirtualService `http[].mirror` to a non-loopback destination, and `http[].mirrors` | Not emitted, because the mirror copy would leave the mesh in cleartext; status lists the field in `deferred_fields`. | Attach a native `request_mirror` plugin with `mirror_protocol: https`. | [mesh.md → Istio Compatibility Gaps](mesh.md#istio-compatibility-gaps) |
| EgressGateway stream-family ports (`tcp`, `mongo`, `redis`, `mysql`, `postgres`) | Experimental and opt-in (`FERRUM_MESH_EGRESS_STREAM_ENABLED`). Relayed as TCP with no protocol-aware mediation: the protocol tag is kept for observability only. | Enforce protocol-level policy at the external service. | [mesh.md → Egress Gateway](mesh.md#egress-gateway-1) |
| NodeWaypoint topology | Experimental until the promotion gates in its ADR close. | Prefer the Sidecar topology (GA) for production. | [mesh_supported_matrix.md](mesh_supported_matrix.md), [node_waypoint_transport_adr.md](plans/node_waypoint_transport_adr.md) |
| eBPF ambient capture | Dev-only: requires a `--features ebpf` build; the default published image refuses eBPF mode before readiness. | Use the `-ebpf` image variants the charts select, or iptables capture. | [mesh.md → Capture / data-path maturity](mesh.md#capture--data-path-maturity) |
| `EnvoyFilter` and `WasmPlugin` | **Not planned.** Not translated. | Use Ferrum custom plugins (`custom_plugins/`). | [mesh.md → Istio Compatibility Gaps](mesh.md#istio-compatibility-gaps) |
