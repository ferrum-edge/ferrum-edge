# Production Readiness Ledger — Ferrum Edge

Product-readiness epic executed 2026-07-12 (orchestrated multi-agent audit + remediation).
Method: four independent read-only audits (deferral markers, docs-vs-code truth, security
posture, ops/CI/release) → findings triaged → fixes implemented via reviewed PRs (codex
review loop + full CI + orchestrator review on every PR) → merged.

## Launch gate summary

| Gate | Status |
|------|--------|
| Feature set implemented or proven out of scope | PASS — zero doc overclaims across README/FEATURES/62 docs; genuine deferrals documented with graceful behavior. Historical umbrella: #2110; live residuals: dedicated issues in the Current residual map |
| All deferral markers resolved or tracked | PASS — ~259 raw markers triaged: 1 medium fixed (PR #2113), lows fixed (#2114) or tracked; completed epic rows reconciled below; live leftovers use dedicated issues |
| Critical/high/medium bugs fixed | PASS — 0 critical/high found in any audit; all 5 mediums fixed and merged |
| Docs truthful vs code | PASS — stale REFACTORING_PLAN.md retired, WEBSOCKET.md/admin_api.md corrected (PR #2112); config/openapi/plugin-priority parity verified clean |
| Security posture verified | PASS — 0 crit/high/med; both lows hardened (PR #2114); CRL revocation now symmetric inbound/outbound (PR #2113) |
| Deployment/CI/release readiness | PASS — tag↔version guard + CHANGELOG policy (PR #2109); flake redness remediated pre-epic (#2057/#2060 fixes + #2103), main monitored green through the epic |

## Merged work (all codex-clean + CI-green + orchestrator-reviewed)

| PR | Closes | Delivered |
|----|--------|-----------|
| #2105 | #2104 | Live two-cluster gate: blanket NEW-TCP REJECT firewall-proves Ambient east-west traversal; self-check asserts dest gateway inbound ports unreachable |
| #2109 | #2107 | release.yml tag↔Cargo-version guard gating all publish jobs; CHANGELOG.md + policy; docs/ci_cd.md |
| #2112 | #2111 | REFACTORING_PLAN.md retired (live remainder → #2110); WEBSOCKET.md tunnel-mode section (verified vs code); admin_api.md LB list |
| #2113 | #2106 | Mesh outbound SPIFFE CRL revocation parity (HBONE + mesh-mTLS pools), consuming the live-reload SharedCrlList slot with reload-race pooling guards; honest revocation docs (unknown-status allowance documented); revoked/unrevoked dial tests |
| #2114 | #2108 | CSR proof-of-possession verification (transport-agnostic, x509-parser verify); FERRUM_ADMIN_JWT_AUDIENCE (strict RFC 7519 default kept + pinned by test); stale UDP deferral message fixed; release image log level error→warn |

## Findings ledger (final)

| ID | Finding | Severity | Disposition |
|----|---------|----------|-------------|
| PR-001 | Ambient live-gate row not firewall-proven | Medium (test integrity) | FIXED (PR #2105) |
| PR-002 | Outbound mesh SPIFFE verification skipped CRLs (inbound-only asymmetry) | Medium (security) | FIXED (PR #2113, 3 codex rounds incl. live-reload slot + race guards) |
| PR-003 | InternalCa CSR path lacked proof-of-possession | Low (hardening) | FIXED (PR #2114 — real PoP verification) |
| PR-004 | SPIFFE Workload API JWT-SVID unimplemented (X.509 complete) | Low | FIXED — [#3675](https://github.com/ferrum-edge/ferrum-edge/pull/3675) resolves [#3617](https://github.com/ferrum-edge/ferrum-edge/issues/3617). `FERRUM_MESH_CA_BACKEND=internal` implements mint / validate / JWT bundle streaming behind `FERRUM_MESH_WORKLOAD_API_ENABLED`, with operator-configured ES256 signing material (restart + multi-replica continuity), **externally-rotated-only signing keys** (an in-process replacement for configured material is refused, since it would diverge per replica and vanish on restart), and a provable rotation overlap for the dev-only ephemeral key. `FetchJWTBundles` never streams an empty map. **Serving a Workload API on `FERRUM_MESH_CA_BACKEND=spire` is refused at startup** because the agent cannot issue for an attested downstream workload; the active SPIRE runtime continues to consume X.509 identity and trust bundles but does not start a JWT-bundle stream |
| PR-005 | k8s controller Merge-Patch status writes (SSA TODO); naming-convention proxy-id | Low | FIXED (PR #2152) — intentional mixed strategy: resourceVersion-guarded RMW for Route `status.parents[]` (Gateway API list ownership), SSA + stable `fieldManager` for Gateway/GatewayClass conditions, plus typed proxy-id mapping. Not a blanket "convert everything to SSA" TODO. |
| PR-006 | Stale "F3 §3.3 UDP not implemented" message | Low (accuracy) | FIXED (PR #2114) |
| PR-007 | Log schema not applied to WsDisconnectLogEntry | Low | FIXED — `WsDisconnectLogEntry` implements `SchemaSerializable`; see `docs/log_schema.md` WebSocket disconnect family |
| PR-008 | Main redness from flakes #2057/#2060 + port races | Medium (ops) | RESOLVED pre-epic (fixes + #2103); main monitored green through epic |
| PR-009 | No release tag↔version guard | Medium (ops) | FIXED (PR #2109) |
| PR-010 | No CHANGELOG/policy | Medium (ops) | FIXED (PR #2109) |
| PR-011 | Admin JWT lacked optional aud validation | Low (hardening) | FIXED (PR #2114; strict default deliberately kept — see below) |
| PR-012 | Release image log level hid startup warns | Low | FIXED (PR #2114) |
| PR-013 | No Helm chart for core gateway modes | Low | FIXED — `charts/ferrum-gateway` deploys database/file/cp/dp (see chart README + `docs/kubernetes_deployment.md`) |
| PR-014 | Stress tests excluded from CI | Low | FIXED — PR CI still excludes the 30k/10k suites; scheduled coverage is `.github/workflows/scaling-regression.yml` |
| PR-015 | Stale REFACTORING_PLAN.md; WEBSOCKET.md/admin_api.md gaps | Medium (stale root doc) | FIXED (PR #2112) |
| PR-016 | Documented feature deferrals (accurately labeled) | Low | PARTIALLY SUPERSEDED — mesh HTTP retry re-screen closed (#2008); remaining product deferrals live in dedicated issues (see Current residual map). #2110 is the historical 2026-07-12 register, not the live backlog. |

## Audit verifications (no action needed — recorded to prevent relitigating)

- Security: admin API single JWT gate with tiered observability exactly per rules; JWT
  validate_exp/nbf + fixed algorithm; constant-time credential comparisons; mesh authz
  DENY-first fail-closed; no secret logging; smuggling guards per RFC 9112; anchored
  resource-id validation; recursive credential rejection in spec extractor; deny.toml
  ignores all rationaled with future expiry; SSRF/DNS-rebinding posture (PR #1933) intact.
- Docs: configuration.md ↔ env_config.rs zero dead vars; openapi.yaml 1:1 with admin
  dispatch; all 82 plugins in openapi; priorities match plugin_execution_order.md.
- Ops: CI aggregate gate has no always()-escape; #[ignore] functional tests DO run
  (nextest --run-ignored=all); shard-coverage gates active; injector/node_agent/migrate
  modes all have functional tests; licenses consistent; Docker ports match docs.

## Deliberate decisions (do not "fix" without revisiting rationale)

- **Admin JWT `aud` unset ⇒ strict**: tokens carrying `aud` are rejected when
  FERRUM_ADMIN_JWT_AUDIENCE is unset (RFC 7519 §4.1.3, jsonwebtoken default, pre-existing
  behavior). Loosening would enable cross-service token replay under HS256 secret reuse.
  Pinned by `test_audience_unset_rejects_aud_bearing_token`.
- **Mesh CRL unknown-revocation allowance**: peers whose revocation status is
  undeterminable (no CRL from their issuing CA) are accepted, matching the shared inbound
  model; removing it would break federated meshes lacking per-CA CRLs. Documented in
  docs/mesh.md.
- Pre-existing intentional trade-offs re-confirmed: WAF body gates, JWKS retain guard,
  dedup try_lock eviction, MCP stale-template serving, H3 streaming-trailer limitation,
  kTLS KeyUpdate userspace fallback, mcp_gateway V1 tool-result rejection.

## Needs human decision

None blocking launch. Post-launch discretionary items that remain open should be
tracked on their **dedicated** issues (not by treating #2110 as an unchanged
snapshot). #2110 stays open only as the historical 2026-07-12 register; after
docs reconciliation merges, root should retick/comment that register so completed
rows (Helm chart, scheduled stress job, mixed k8s status ownership, WsDisconnect
schema, closed #2008/#2013/#2475, TLS-SNI L4 support) are not re-opened from the
issue body alone.

## Current residual map (live dedicated trackers)

**Last reconciled:** 2026-08-06 (issue #3627; verified against `origin/main`).

| Residual | Live issue(s) | Notes |
|----------|---------------|-------|
| EgressGateway UDP `ServiceEntry` materialization | #3263 | Explicit mesh product deferral |
| Provenance-complete mesh/HBONE/DNS perf baselines | #3332 | Harnesses exist; baseline tables still `_TBD_` |
| Live OIDC / OAuth2 introspection coverage | #3333 | |
| NodeWaypoint observability + promotion gates | #3334 | |
| Vendored-patch upstream filing / retirement | `docs/vendored-patch-lifecycle.json` + weekly `dependency-audit` | Repository-owned lifecycle inventory; closes #3335 |
| Admin CRUD refactor (retired plan remainder) | #2110 (historical) | Discretionary; fold into future admin-surface work |
| Mesh/SPIRE CA-health signal + startup contract | #3608 | Documented SPIRE contract vs runtime wiring |
| Cross-region CP failover topology | #3610 | `multi_region_ha.md` vs CP rejection/failover fence |
| CP/K8s authoritative mesh config revision | #3611 | DP stale-fallback gate inert in flagship K8s topology |
| Gateway API port-aware route representation | #3612 | Done — per-listener identity, real listener binding, per-listener retention |
| OIDC RP pending login state (HA) | #3613 | Process-local state breaks non-sticky multi-replica login |
| `ai_stream_router` Anthropic multimodal content | #3616 | Silent drop vs Gemini fail-closed path |
| TCP outbound PROXY protocol v2 | #3618 | Inbound only today |
| TCP/kTLS kernel splice (frontend-TLS relay) | #3619 | Unbuffered rustls handshake leaves splice inert |
| HTTP/3 plain-HTTP/WebSocket to mesh-tagged targets | #3620 | H3 retry rotation must skip fail-closed targets |
| Ambient UDP enrolled-destination round trip | #3621 | Source-capture live gate exists; destination pod-netns relay + tc-inbound admit not yet live-gated |
| Direct-H2 in-path body-size limits | #3622 | Default nonzero limits still force reqwest path |
| Admin read-only write audit logging | #3623 | Docs promise logging/counts that do not exist |
| Env-only reads ignoring `ferrum.conf` | #3624 | `FERRUM_LOG_REDACT_METADATA_KEYS`, `FERRUM_NODE_ID`, validation-client gates |
| Gateway SVID auto-refresh (external/inline) | #3625 | Static until restart or manual rotate |

**Implemented since the epic (do not re-open from stale checklists):** remote-discovery
JWT audience binding (#2475); Ambient UDP capture producer + live source-capture e2e
(#2013 / #2038); VirtualService `tls[]` SNI passthrough L4 routing (see
`docs/mesh_supported_matrix.md` + `tests/integration/mesh_l7_routing_tests.rs`);
AI semantic-firewall token windows (#3302); subset-scoped Istio HTTP connection-pool
policy (#3547, closing #3228 / #3240–#3242); `ai_stream_router` `google_gemini`
adapter (#3299); pre-first-byte stream-router fallback (#3328 — explicit admission
rejection); native-gRPC transcript capture (#3304); native SMTP/email notification
channel (#3329); MongoDB replica-set change-stream wakeups (#3330); multicluster
poller partition / last-good live gate (#3331); CNI chained-install lifecycle
evidence including live kind install/uninstall recovery (#3609).
