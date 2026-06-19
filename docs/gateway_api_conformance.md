# Gateway API Conformance

## Independent Validation

Baseline commit inspected before remediation: `1252246777bdaa8fcbe6b401ffdc9020d7f71e11` (`12522467 Merge pull request #1826 from ferrum-edge/codex/dr-proxy-route-rebuild`).

The previous `.github/workflows/gateway-api-conformance.yml` defaulted to Gateway API `v1.5.1`, advertised `Gateway,HTTPRoute`, and ran only these upstream tests:

- `GatewayClassObservedGenerationBump`
- `GatewayObservedGenerationBump`
- `HTTPRouteObservedGenerationBump`
- `HTTPRouteInvalidCrossNamespaceParentRef`

Manual dispatch of that workflow on `main` succeeded in run `27799052406` on June 19, 2026. The artifact showed only the control-plane deployment and Service in the `ferrum` namespace. No Ferrum data-plane deployment, pod, listener Service, NodePort, or LoadBalancer was installed. The upstream JSON marked request-path tests such as `HTTPRouteSimpleSameNamespace`, `HTTPRouteWeight`, and `HTTPRouteReferenceGrant` as skipped, and there were no client request traces against a Ferrum listener. That run therefore validated status/controller behavior only; it did not prove data-plane conformance.

## Supported-Feature Matrix

| Gateway API surface | Claimed in CI | Current Ferrum behavior |
|---|---:|---|
| `GatewayClass` | Yes | Watched and status-patched for `ferrum.io/gateway-controller` |
| `Gateway` HTTP listeners | Yes | Translated into Ferrum HTTP listener materialization; listener status and `Programmed` are patched |
| `Gateway` HTTPS listeners | Yes, as part of `GATEWAY-HTTP` | Translated onto the HTTPS frontend with the test TLS certificate mounted into the data plane |
| `HTTPRoute` hostname, path, method, header, and query matching | Yes | Translated into proxies plus ordered `mesh_route_dispatch` rules where predicate matching is needed |
| `HTTPRoute` weighted `backendRefs` | Yes | Multiple non-zero backends create a weighted upstream; zero-weight-only rules fail closed through a blackhole backend |
| Cross-namespace `HTTPRoute.backendRefs` | Yes | Requires an exact `ReferenceGrant`; missing grants are rejected and unresolved |
| Cross-namespace `parentRefs` | Yes | Allowed only when the referenced Gateway listener permits the route namespace |
| Invalid backend references | Yes | Missing Services and non-Service backend target kinds are reported as unresolved and fail closed |
| Backend failure | Yes | Traffic to unavailable generated backends must return an error response rather than falling through |
| Route update and deletion | Yes | Reconciliation regenerates live proxy/upstream/plugin config; deletion removes the route from live config |
| `GRPCRoute` | Not claimed by the `GATEWAY-HTTP` gate | Watched and partially translated through HTTP/gRPC routing, but not advertised as a passing upstream `GATEWAY-GRPC` profile until request traffic conformance is added |
| `TLSRoute` and `TCPRoute` | Not claimed | Watched/translated for L4 experiments, but not advertised as supported Gateway API conformance profiles |
| `UDPRoute`, `BackendTLSPolicy`, `ListenerSet`, `BackendLBPolicy` | No | Not claimed as effective Gateway API conformance features |

## CI Evidence

The Gateway API conformance workflows now deploy the same lab:

- Ferrum control plane/controller with Gateway API watches enabled.
- A routable Ferrum data-plane deployment and NodePort Service mapped to host ports 80 and 443 in kind.
- Two HTTP echo backend namespaces.
- `GatewayClass`, `Gateway`, `HTTPRoute`, `GRPCRoute`, and `ReferenceGrant` resources for direct black-box checks.
- The upstream Gateway API conformance suite pinned by `GATEWAY_API_VERSION`, defaulting to `v1.5.1`, running the complete `GATEWAY-HTTP` profile with explicit supported features `Gateway,ReferenceGrant,HTTPRoute`.

Direct black-box checks cover hostname, path, method, headers, weighted backend selection, cross-namespace references, invalid references, backend failure, TLS, route updates, and route deletion. Diagnostics and the upstream standard conformance report are uploaded from `conformance-results/` as retained CI artifacts.
