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
| `ai_stream_router` `google_gemini` adapter | Implemented — [#3299](https://github.com/ferrum-edge/ferrum-edge/issues/3299) |
| Subset-scoped Istio HTTP connection-pool policy | Implemented by [#3547](https://github.com/ferrum-edge/ferrum-edge/pull/3547), resolving [#3228](https://github.com/ferrum-edge/ferrum-edge/issues/3228) / [#3240](https://github.com/ferrum-edge/ferrum-edge/issues/3240)–[#3242](https://github.com/ferrum-edge/ferrum-edge/issues/3242) |
| AI semantic-firewall token windows | Implemented — [#3302](https://github.com/ferrum-edge/ferrum-edge/issues/3302) (`streaming.window: tokens` with explicit bounded tokenizer) |
| Native-gRPC transcript capture | Implemented — [#3304](https://github.com/ferrum-edge/ferrum-edge/issues/3304) (descriptor-based gRPC enrollment in `src/plugins/ai_transcript_audit.rs`) |
| Pre-first-byte stream-router fallback | Closed [#3328](https://github.com/ferrum-edge/ferrum-edge/issues/3328) — explicit admission rejection (issue #3328) |
| Native SMTP/email notification channel | Implemented — [#3329](https://github.com/ferrum-edge/ferrum-edge/issues/3329) (`src/notifications/channels/email.rs`) |
| MongoDB replica-set change-stream wakeups | Implemented — [#3330](https://github.com/ferrum-edge/ferrum-edge/issues/3330) (`src/config/config_change_watch.rs` + `mongo_store.rs`) |
| Multicluster poller partition / last-good live gate | Implemented — [#3331](https://github.com/ferrum-edge/ferrum-edge/issues/3331) (`.github/workflows/multicluster-poller-partition-live.yml`) |
| SPIFFE Workload API JWT-SVID mint/validate/bundles | Implemented by [#3675](https://github.com/ferrum-edge/ferrum-edge/pull/3675), resolving [#3617](https://github.com/ferrum-edge/ferrum-edge/issues/3617); empty bundle success removed and the SPIRE serving boundary documented |
| EgressGateway UDP `ServiceEntry` materialization | Implemented — [#3263](https://github.com/ferrum-edge/ferrum-edge/issues/3263) (external UDP ports materialize a datagram-over-mesh destination allowlist consumed by the gateway's authenticated mesh CONNECT terminator, plus the source-side `Sidecar`/`Ambient` producer that originates the identity-pinned `udp` CONNECT; no UDP/DTLS listener, by design) |

## Live dedicated trackers (current backlog)

**Last reconciled:** 2026-08-06 (issue #3627; verified against `origin/main`).

| Residual | Issue(s) | Notes |
|---|---|---|
| Mesh/HBONE/DNS perf baseline publication | [#3332](https://github.com/ferrum-edge/ferrum-edge/issues/3332) | Harnesses exist; `baseline.md` tables still `_TBD_` |
| Live OIDC / OAuth2 introspection coverage | [#3333](https://github.com/ferrum-edge/ferrum-edge/issues/3333) | |
| NodeWaypoint observability + promotion gates | [#3334](https://github.com/ferrum-edge/ferrum-edge/issues/3334) | |
| Vendored-patch upstream filing / retirement | `docs/vendored-patch-lifecycle.json` + weekly `dependency-audit` | Replaces #3335 as the sole tracker |
| Mesh/SPIRE CA-health signal + startup contract | [#3608](https://github.com/ferrum-edge/ferrum-edge/issues/3608) | |
| CNI ferrum-cni chaining uninstall/rollback | [#3609](https://github.com/ferrum-edge/ferrum-edge/issues/3609) | |
| Cross-region CP failover topology | [#3610](https://github.com/ferrum-edge/ferrum-edge/issues/3610) | |
| CP/K8s authoritative mesh config revision | [#3611](https://github.com/ferrum-edge/ferrum-edge/issues/3611) | |
| Gateway API port-aware route representation | [#3612](https://github.com/ferrum-edge/ferrum-edge/issues/3612) | Done — `GatewayApiListenerKey` identity, real per-listener socket binding + reload/withdrawal, per-listener cross-kind retention, and `Conflicted` status for same-port incompatible-shape refusals |
| OIDC RP pending login state (HA) | [#3613](https://github.com/ferrum-edge/ferrum-edge/issues/3613) | |
| `ai_stream_router` Anthropic multimodal content | [#3616](https://github.com/ferrum-edge/ferrum-edge/issues/3616) | |
| TCP outbound PROXY protocol v2 | [#3618](https://github.com/ferrum-edge/ferrum-edge/issues/3618) | |
| TCP/kTLS kernel splice (frontend-TLS relay) | [#3619](https://github.com/ferrum-edge/ferrum-edge/issues/3619) | |
| HTTP/3 plain-HTTP/WebSocket to mesh-tagged targets | [#3620](https://github.com/ferrum-edge/ferrum-edge/issues/3620) | |
| Ambient UDP enrolled-destination round trip | [#3621](https://github.com/ferrum-edge/ferrum-edge/issues/3621) | Source-capture live gate exists; destination pod-netns relay not yet live-gated |
| Direct-H2 in-path body-size limits | [#3622](https://github.com/ferrum-edge/ferrum-edge/issues/3622) | |
| Admin read-only write audit logging | [#3623](https://github.com/ferrum-edge/ferrum-edge/issues/3623) | |
| Env-only reads ignoring `ferrum.conf` | [#3624](https://github.com/ferrum-edge/ferrum-edge/issues/3624) | |
| Gateway SVID auto-refresh (external/inline) | [#3625](https://github.com/ferrum-edge/ferrum-edge/issues/3625) | |

## Documented deferrals without a dedicated issue (in-place docs)

| Topic | Status | Anchor |
|---|---|---|
| DR `connectionPool.http.maxRequestsPerConnection` | Parsed/validated, not enforced; listed in K8s `deferred_fields` | [`docs/mesh.md`](../mesh.md), [`docs/mesh_supported_matrix.md`](../mesh_supported_matrix.md) |
| Mesh CP per-DP slice-version drift endpoint | Done (#3265) | [`docs/mesh.md`](../mesh.md) |
| EgressGateway TCP stream experimental | Behind `FERRUM_MESH_EGRESS_STREAM_ENABLED=false` default | [`docs/mesh.md`](../mesh.md) |

## #2110-only discretionary remnants

| Item | Notes |
|---|---|
| Admin CRUD refactor (retired `REFACTORING_PLAN.md` remainder) | Discretionary; fold into future admin-surface work |

## Explicit non-goals (unchanged)

- **EnvoyFilter / WasmPlugin** — explicitly not planned; rejected at config source
  ([`docs/mesh.md`](../mesh.md)). Listed in #2110 for completeness only; no
  implementation tracker.
