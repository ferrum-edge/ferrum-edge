# Issue #2110 — historical deferral register

**Captured:** 2026-07-12 production-readiness epic (umbrella register).

**Role:** Historical snapshot only — not the live product backlog.

**Current source of truth:** [`PRODUCTION_READINESS.md`](../../PRODUCTION_READINESS.md)
(Current residual map) and the dedicated issues cited below.

GitHub issue [#2110](https://github.com/ferrum-edge/ferrum-edge/issues/2110)
remains open as the historical register; use this file plus
`PRODUCTION_READINESS.md` when screening agents or docs against the 2026-07-12
checkbox list.

Protected automation note: `tests/performance/mesh/README.md` is a frozen
Trusted Cross surface (every path under `tests/performance/` is protected,
including Markdown). Its historical "Benches deferred (not yet implemented)"
prose is **not** the current backlog source of truth and must stay unchanged.
Current mesh HBONE/DNS perf status lives in
[`docs/protocol_perf_regression.md`](../protocol_perf_regression.md)
(`mesh-hbone-e2e` / `mesh-dns-e2e` suites; residual [#3332](https://github.com/ferrum-edge/ferrum-edge/issues/3332)).

## Completed or superseded (do not reopen from #2110 alone)

| #2110 row | Resolution |
|---|---|
| Mesh HTTP retry-loop transport re-screen gap | Closed [#2008](https://github.com/ferrum-edge/ferrum-edge/issues/2008) |
| k8s controller status writer (Merge Patch → SSA) | [#2152](https://github.com/ferrum-edge/ferrum-edge/pull/2152) — intentional mixed strategy: resourceVersion-guarded RMW for Gateway API `Route.status.parents[]`, SSA + stable `fieldManager` for Gateway/GatewayClass conditions |
| k8s controller proxy-id naming convention | [#2152](https://github.com/ferrum-edge/ferrum-edge/pull/2152) — typed proxy-id mapping |
| Helm chart for core gateway modes | Shipped — [`charts/ferrum-gateway`](../../charts/ferrum-gateway/README.md), [`docs/kubernetes_deployment.md`](../kubernetes_deployment.md) |
| Scheduled stress tests excluded from PR CI | [`.github/workflows/scaling-regression.yml`](../../.github/workflows/scaling-regression.yml) |
| `WsDisconnectLogEntry` log schema | Implemented — [`docs/log_schema.md`](../log_schema.md) WebSocket disconnect family |
| Mesh TLS-SNI L4 routing | Supported — VirtualService `tls[]` SNI passthrough (`sniHosts`); see [`docs/mesh_supported_matrix.md`](../mesh_supported_matrix.md) and `tests/integration/mesh_l7_routing_tests.rs` |
| Remote-discovery JWT audience binding | Implemented — closed [#2475](https://github.com/ferrum-edge/ferrum-edge/issues/2475) |

## Live dedicated trackers (current backlog)

| Residual | Issue(s) | Notes |
|---|---|---|
| Subset-scoped Istio HTTP connection-pool policy | [#3228](https://github.com/ferrum-edge/ferrum-edge/issues/3228) / [#3240](https://github.com/ferrum-edge/ferrum-edge/issues/3240)–[#3242](https://github.com/ferrum-edge/ferrum-edge/issues/3242) | `h2UpgradePolicy`, `maxRetries`, `http1MaxPendingRequests` inside subsets |
| EgressGateway UDP `ServiceEntry` materialization | [#3263](https://github.com/ferrum-edge/ferrum-edge/issues/3263) | HTTP/TCP stream egress exists; UDP ports still skipped |
| `ai_stream_router` `google_gemini` adapter | [#3299](https://github.com/ferrum-edge/ferrum-edge/issues/3299) | Config accepted; construction fails closed until implemented |
| AI semantic-firewall token windows | [#3302](https://github.com/ferrum-edge/ferrum-edge/issues/3302) | `streaming.window: tokens` rejected |
| Native-gRPC transcript capture | [#3304](https://github.com/ferrum-edge/ferrum-edge/issues/3304) | HTTP-only today |
| Pre-first-byte stream-router fallback | [#3328](https://github.com/ferrum-edge/ferrum-edge/issues/3328) | Implement or explicitly reject |
| Native SMTP/email notification channel | [#3329](https://github.com/ferrum-edge/ferrum-edge/issues/3329) | |
| MongoDB replica-set change-stream wakeups | [#3330](https://github.com/ferrum-edge/ferrum-edge/issues/3330) | Polling remains authoritative backstop |
| Multicluster poller partition / last-good live gate | [#3331](https://github.com/ferrum-edge/ferrum-edge/issues/3331) | File-config fixture does not exercise pollers |
| Mesh/HBONE/DNS perf baseline publication | [#3332](https://github.com/ferrum-edge/ferrum-edge/issues/3332) | Harnesses exist; `baseline.md` tables still `_TBD_` |
| Live OIDC / OAuth2 introspection coverage | [#3333](https://github.com/ferrum-edge/ferrum-edge/issues/3333) | |
| NodeWaypoint observability + promotion gates | [#3334](https://github.com/ferrum-edge/ferrum-edge/issues/3334) | |
| Vendored-patch upstream filing / retirement | `docs/vendored-patch-lifecycle.json` + weekly `dependency-audit` | Replaces #3335 as the sole tracker |

## Documented deferrals without a dedicated issue (in-place docs)

| Topic | Status | Anchor |
|---|---|---|
| TCP/UDP outbound PROXY protocol | Inbound only today; outbound not implemented | [`docs/tcp_udp_proxy.md`](../tcp_udp_proxy.md) |
| DR `connectionPool.http.maxRequestsPerConnection` | Parsed/validated, not enforced; listed in K8s `deferred_fields` | [`docs/mesh.md`](../mesh.md), [`docs/mesh_supported_matrix.md`](../mesh_supported_matrix.md) |
| Mesh CP per-DP slice-version drift endpoint | Done via #3265 (`GET /cluster` `mesh_slice_convergence`) | [`docs/mesh.md`](../mesh.md), [`docs/admin_api.md`](../admin_api.md) |
| EgressGateway TCP stream experimental | Behind `FERRUM_MESH_EGRESS_STREAM_ENABLED=false` default | [`docs/mesh.md`](../mesh.md) |

## #2110-only discretionary remnants

| Item | Notes |
|---|---|
| SPIFFE Workload API JWT-SVID mint/validate | X.509-SVID path complete; JWT-SVID still deferred in `src/identity/workload_api/` |
| Admin CRUD refactor (retired `REFACTORING_PLAN.md` remainder) | Discretionary; fold into future admin-surface work |

## Explicit non-goals (unchanged)

- **EnvoyFilter / WasmPlugin** — explicitly not planned; rejected at config source
  ([`docs/mesh.md`](../mesh.md)). Listed in #2110 for completeness only; no
  implementation tracker.
