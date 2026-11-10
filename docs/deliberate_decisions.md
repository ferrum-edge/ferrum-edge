# Deliberate Decisions

Trade-offs Ferrum Edge makes on purpose. Each entry states the behaviour, why
the alternative was rejected, and the test that pins it. Do not "fix" one of
these without revisiting its rationale; change the entry in the same pull
request when the decision itself changes.

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
- Other intentional trade-offs, documented with their subsystems: WAF body gates, JWKS retain guard,
  dedup try_lock eviction, MCP stale-template serving, H3 streaming-trailer limitation,
  kTLS KeyUpdate userspace fallback, mcp_gateway V1 tool-result rejection.
