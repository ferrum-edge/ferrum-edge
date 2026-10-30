# Production Readiness Ledger — Ferrum Edge

Product-readiness epic executed 2026-07-12 (orchestrated multi-agent audit + remediation).
Method: four independent read-only audits (deferral markers, docs-vs-code truth, security
posture, ops/CI/release) → findings triaged → fixes implemented via reviewed PRs (codex
review loop + full CI + orchestrator review on every PR) → merged.

## Live launch gate (removed)

The automated launch-readiness gate that used to own this section was removed
(workflows `launch-readiness.yml`, `launch-integrity.yml`,
`launch-advisory-trust.yml`, their verifiers, the blocker policy and exemption
data, and the `validate-launch-readiness` job in `.github/workflows/release.yml`).
Every blocker it tracked had been closed: its last evaluation on `main` reported
`"blocking_issues": []` with `critical 0 / high 0 / medium 0`.

There is therefore **no automated go/no-go launch signal in this repository**.
Release readiness is a human judgement, and a `v*` tag no longer requires a
computed launch verdict or a private-advisory attestation. The historical
evidence below is exactly that — historical — and was never a live verdict.

<!-- launch-readiness:historical -->

## Historical epic summary (not the live gate)

The tables below record the 2026-07-12 product-readiness epic and later ledger
reconciliations. They are **historical evidence**, not the live launch verdict.

| Gate | Historical status (epic / audit evidence) |
|------|--------|
| Feature set implemented or proven out of scope | Historical PASS — zero doc overclaims across README/FEATURES/62 docs; genuine deferrals documented with graceful behavior. Historical umbrella: #2110; later residuals: dedicated issues (see Current residual map; no automated launch gate) |
| All deferral markers resolved or tracked | Historical PASS — ~259 raw markers triaged: 1 medium fixed (PR #2113), lows fixed (#2114) or tracked; completed epic rows reconciled below; live leftovers use dedicated issues |
| Critical/high/medium bugs fixed | Historical static-audit evidence — 0 *new untracked* critical/high found in the 2026-07-12 audits; all 5 epic mediums fixed and merged. **Not** a claim about the current launch backlog |
| Docs truthful vs code | Historical PASS — stale REFACTORING_PLAN.md retired, WEBSOCKET.md/admin_api.md corrected (PR #2112); config/openapi/plugin-priority parity verified clean |
| Security posture verified | Historical PASS — 0 crit/high/med in the epic security audit; both lows hardened (PR #2114); CRL revocation now symmetric inbound/outbound (PR #2113) |
| Deployment/CI/release readiness | Historical PASS — tag↔version guard + CHANGELOG policy (PR #2109); flake redness remediated pre-epic (#2057/#2060 fixes + #2103), main monitored green through the epic |

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

- **UDP response amplification is bounded by default on every source**: a
  `udp`/`dtls` proxy that names no `udp_max_response_amplification_factor` is
  normalized to the finite default `8.0` in `Proxy::normalize_fields()` —
  file mode, database mode, the admin API, CP→DP distribution, mesh
  materialization, and Gateway API `UDPRoute` translation alike (issue #4515).
  UDP has no handshake, so an unbounded reply budget makes any
  small-request/large-response backend a spoofed-source reflector; the default
  must not depend on who authored the proxy. Unlimited is opt-in via the
  explicit `0` sentinel, which is accepted only on UDP/DTLS proxies and emits a
  startup warning on the affected listener. Do not restore "unset means
  unlimited". Pinned by `tests/unit/config/udp_amplification_default_tests.rs`
  and the two default/sentinel cases in
  `tests/functional/functional_udp_proxy_test.rs`.
- **Admin JWT `aud` unset ⇒ strict**: tokens carrying `aud` are rejected when
  FERRUM_ADMIN_JWT_AUDIENCE is unset (RFC 7519 §4.1.3, jsonwebtoken default, pre-existing
  behavior). Loosening would enable cross-service token replay under HS256 secret reuse.
  Pinned by `test_audience_unset_rejects_aud_bearing_token`.
- **Admin `ns`-claim enforcement auto-engages on a multi-namespace CP**:
  `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM` defaults to `false`, but `cp` mode ORs it
  with `CpScope::requires_namespace_claim_by_default()`, so a CP whose
  `FERRUM_CP_NAMESPACES` names more than one namespace (or `*`) requires an `ns`
  claim on namespace-scoped admin routes even with the flag unset (issue #4529).
  The two control planes of one process must agree that namespace is an
  authorization boundary: the REST plane serialises consumer credentials through
  `GET /backup` and can wipe a tenant through `POST /restore`, so it must not
  accept a token the gRPC plane already refuses. This is intentionally breaking
  for tokens minted without `ns`. Do not restore the flag-only gate. Pinned by
  `admin_namespace_claim_derivation_matches_cp_scope` and
  `multi_namespace_cp_scope_engages_backup_tenancy_without_the_env_flag`.
- **Mesh CRL unknown-revocation allowance**: peers whose revocation status is
  undeterminable (no CRL from their issuing CA) are accepted, matching the shared inbound
  model; removing it would break federated meshes lacking per-CA CRLs. Documented in
  docs/mesh.md.
- **Expired revocation material refuses startup**: `tls::load_crls` refuses a
  CRL past its `nextUpdate` (and a stapled OCSP response past its own), and
  that `Err` is `?`-propagated out of every `startup_security::load_crls_from_env`
  caller — database, file, cp, dp, mesh, node_agent — so the process exits
  rather than booting. This is the *fail-closed* half of a real trade-off: a
  pod that restarts after `nextUpdate` does not come back, which turns a
  forgotten CRL refresh job into a fleet-wide outage. Booting anyway would
  serve without revocation enforcement for that issuer, i.e. fail-open, and a
  "refuse just that issuer" variant is the same outage with more machinery.
  The mitigation is lead time, not softening: `FERRUM_TLS_CRL_EXPIRY_WARNING_DAYS`
  (default 30) warns at load and again on every hourly staple re-check, the
  `ferrum_tls_revocation_expiry_seconds` gauge
  and the chart's `FerrumGatewayRevocationMaterialExpiringSoon` alert make it
  recurring, and live reload
  (`FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` / `FERRUM_BACKEND_TLS_LIVE_RELOAD_ENABLED`)
  adopts a refreshed copy without a restart. Documented in
  docs/frontend_tls.md and docs/backend_mtls.md; pinned by
  `tests/unit/tls/crl_policy_tests.rs` (issue #4505).
- **A served OCSP staple is dropped, not kept, once it reaches `nextUpdate`**:
  `tls::ocsp_recheck` re-evaluates every served staple hourly (a constant, not
  an env var) and retires one that has reached its `nextUpdate` on the exact
  certificate resolver the listener serves — so it reaches HTTP/1.1, HTTP/2,
  HTTP/3, TCP+TLS and admin HTTPS at once, with live reload on **or off**. This
  is the opposite trade-off from the startup refusal above and deliberately so:
  a stale staple is a hard handshake failure for any client that checks it,
  while no staple falls back to that client's own revocation behaviour, so
  "keep serving what we have" is the strictly worse of the two. It does not
  make the gateway fail open — nothing about certificate or CRL admission
  changes — and it does not fetch anything, because Ferrum still has no OCSP
  responder client; re-attaching a fresh response remains the operator's fetch
  loop plus live reload (or a restart). Documented in docs/frontend_tls.md;
  pinned by `tests/unit/tls/ocsp_validation_tests.rs` and
  `tests/integration/frontend_tls_live_reload_tests.rs` (issue #4505).
- **Fail-fast panics in shipping profiles**: `[profile.release]`,
  `[profile.ci-release]` (inherits `release`), and `[profile.max-perf]` set
  `panic = "abort"` (issue #4166). A panic anywhere in the process —
  including a background poller, accept loop, k8s controller task, or
  notification settle callback — terminates the gateway. There is no
  in-process panic recovery in shipping binaries: smaller binaries (no
  unwind tables) and fail-fast after a violated invariant beat restarting a
  task whose process state may already be inconsistent. Background-task
  supervisors still handle non-panic unexpected exits (I/O errors,
  unexpected completion, cancellation) and keep serving last-known-good
  config where that policy already exists. Dev/test/`pr-build` keep
  `panic = "unwind"` so the suite can observe `JoinError::is_panic()`;
  those tests are not shipping behavior. Operators must run a process
  supervisor (systemd, Kubernetes `restartPolicy`). Pinned by
  `tests/unit/gateway_core/build_profile_panic_strategy_tests.rs`.
- Pre-existing intentional trade-offs re-confirmed: WAF body gates, JWKS retain guard,
  dedup try_lock eviction, MCP stale-template serving, H3 streaming-trailer limitation,
  kTLS KeyUpdate userspace fallback, mcp_gateway V1 tool-result rejection.

## Needs human decision (historical note)

Launch-blocking human decisions are no longer represented by any automated gate
or structured exemption file; both were removed. This historical note must not be
read as a clean launch signal. Post-launch discretionary items that remain open
are tracked on their **dedicated** issues (not by treating #2110 as an unchanged
snapshot). GitHub issue #2110 is CLOSED (COMPLETED, 2026-07-28) and remains the
historical 2026-07-12 register only via `docs/backlog/issue_2110_register.md`.
Completed rows (Helm chart, scheduled stress job, mixed k8s status ownership,
WsDisconnect schema, closed #2008/#2013/#2475, TLS-SNI L4 support) must not be
re-opened from the issue body alone.

## Current residual map

**Last narrative reconciliation:** 2026-10-30 (previously 2026-08-18, issue #3893). PR #4010 removed the
launch-readiness workflows, verifiers, policy inventory, and the
`validate-launch-readiness` release job. There is no live gate and no
open-inventory artifact. This map is a human-maintained leftover ledger from
the 2026-07-12 epic, not an automated go/no-go signal and not an inventory of
every open GitHub issue.

The residual map is currently **empty**: the last two rows (#3332 and #3892)
closed on 2026-08-21 and are recorded below. Closed former residuals are
recorded under Implemented since the epic. Ordinary post-launch bugs and CI
trackers live on their dedicated issues.

**Implemented since the epic (do not re-open from stale checklists):** remote-discovery
JWT audience binding (#2475); Ambient UDP capture producer + live source-capture e2e
(#2013 / #2038); Ambient UDP enrolled-destination round trip (#3621 —
`functional_mesh_live_source_capture_udp_manager_hbone_round_trip` proves the
source-capture/HBONE/destination-netns relay, while `node-waypoint-ebpf-live`
proves the marked backend datagram crosses the enrolled-pod `tc_inbound` guard);
VirtualService `tls[]` SNI passthrough L4 routing (see
`docs/mesh_supported_matrix.md` + `tests/integration/mesh_l7_routing_tests.rs`);
AI semantic-firewall token windows (#3302); subset-scoped Istio HTTP connection-pool
policy (#3547, closing #3228 / #3240–#3242); `ai_stream_router` `google_gemini`
adapter (#3299); pre-first-byte stream-router fallback (#3328 — explicit admission
rejection); native-gRPC transcript capture (#3304); native SMTP/email notification
channel (#3329); MongoDB replica-set change-stream wakeups (#3330); multicluster
poller partition / last-good live gate (#3331); CNI chained-install lifecycle
evidence including live kind install/uninstall recovery (#3609). Admin CRUD
refactor remainder from retired `REFACTORING_PLAN.md` is discretionary historical
text in the #2110 register; #2110 itself is CLOSED and is not a live tracker.

Moved off the residual map in the 2026-08-18 reconcile (the last two rows in the
2026-10-30 reconcile; all CLOSED / COMPLETED; closing PR from
`closedByPullRequestsReferences`):

| Residual | Closed | Closing PR |
|----------|--------|------------|
| EgressGateway UDP `ServiceEntry` materialization | #3263 (2026-08-08) | #3671 |
| Live OIDC / OAuth2 introspection coverage | #3333 (2026-08-04) | #3552 |
| NodeWaypoint observability + promotion gates | #3334 (2026-07-29) | #3388 (follow-up #3427) |
| Vendored-patch upstream filing / retirement | #3335 (2026-07-30) | #3446 (`docs/vendored-patch-lifecycle.json` + weekly `dependency-audit`) |
| Mesh/SPIRE CA-health signal + startup contract | #3608 (2026-08-08) | #3668 |
| Cross-region CP failover topology | #3610 (2026-08-08) | #3640 |
| CP/K8s authoritative mesh config revision | #3611 (2026-08-09) | #3680 |
| Gateway API port-aware route representation | #3612 (2026-08-09) | #3677 |
| OIDC RP pending login state (HA) | #3613 (2026-08-08) | #3672 |
| `ai_stream_router` Anthropic multimodal content | #3616 (2026-08-08) | #3641 |
| TCP outbound PROXY protocol v2 | #3618 (2026-08-08) | #3647 |
| TCP/kTLS kernel splice (frontend-TLS relay) | #3619 (2026-08-09) | #3670 |
| HTTP/3 plain-HTTP/WebSocket to mesh-tagged targets | #3620 (2026-08-14) | #3798 |
| Direct-H2 in-path body-size limits | #3622 (2026-08-08) | #3646 |
| Admin read-only write audit logging | #3623 (2026-08-08) | #3643 |
| Env-only reads ignoring `ferrum.conf` | #3624 (2026-08-08) | #3644 |
| Gateway SVID auto-refresh (external/inline) | #3625 (2026-08-09) | #3669 |
| `stable_file` delete/recreate churn flake | #3891 (2026-08-17) | #3894 (2026-08-15 CI addition; not an epic residual) |
| Provenance-complete mesh/HBONE/DNS perf baselines | #3332 (2026-08-21) | #4088 |
| Scheduled Scaling Regression red (JWT expiry / 503 retry) | #3892 (2026-08-21) | #3895 |
