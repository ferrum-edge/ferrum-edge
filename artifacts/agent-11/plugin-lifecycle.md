# Agent 11 — Plugin lifecycle launch-readiness

Investigation only. No production Rust changes.

## Identity

| Field | Value |
|---|---|
| Agent | Ferrum Edge Launch-Readiness Agent 11 |
| Domain | Plugin lifecycle, WASM/Lua/JS/native, config validation, crash isolation, hot reload, ordering |
| Product SHA | `bf05855f8429e466511610f9072f666b45cd309a` (`origin/main`, `bf05855f` Merge PR #4319) |
| Binary | `target/debug/ferrum-edge` (default features, `RUSTFLAGS='-C debuginfo=0'`, `cargo --config 'build.rustc-wrapper=""' build --jobs 1 --bin ferrum-edge`) |
| Ports | `127.0.0.1:22000` proxy, `:22001` admin, `:22002` echo backend |
| Prefix | `fe-agent-11-` |
| Date | 2026-08-30 |

## Verdict (pending empirical matrix)

**BLOCKED on compile + file-mode matrix.** Source review is complete. HOLD items #4076 and #4038 do not reopen. Do not duplicate them.

## Charter cells

| Cell | Status | Notes |
|---|---|---|
| Plugin load / fail / reload | SOURCE PASS; runtime pending | Unknown enabled names reject the generation. `OptionalFailOpen` omits. `FailClosed` / `KeepLastKnownGood` reject publication (reload keeps last cache). File-mode SIGHUP uses atomic `PluginCache` swap. |
| `deny_unknown_fields` | MIXED (source) | `PluginConfig` envelope is `#[serde(deny_unknown_fields)]`. Most built-ins reject unknown `config` keys. Residual ignore-typo constructors observed (see findings). |
| Crash isolation | N/A / documented | Native in-process only. Shipping profiles `panic = "abort"`; no hook `catch_unwind`. WASM/Lua/JS hosts do not exist. |
| Ordering | SOURCE PASS; runtime pending | Stable `sort_by_key(priority)`; `priority_override` via `PluginInstanceWrapper`. |
| #4076 CLOSED audit flake | HOLD | Fix still present (`Utc::now()` relative stamps). Do not reopen. |
| #4038 CLOSED file-mode `proxy_id` vs `proxies[].plugins` | HOLD | Docs match runtime. Validate still admits ID-only. Do not reopen. |

## Runtimes: WASM / Lua / JS / native

**Observed.** Custom plugins are compile-time native Rust (`custom_plugins/*.rs`, `create_plugin` + `failure_policy`). Default and Docker builds do not register `custom_plugins/examples/`. There is no wasmtime/wasmer/mlua/quickjs/extism (or equivalent) dependency. `docs/mesh.md` and `docs/mesh_supported_matrix.md` mark Istio `WasmPlugin` / `EnvoyFilter` as **not planned**. `serverless_function` invokes HTTP/AWS Lambda; it is not an in-process JS/WASM VM.

**Expected.** Charter asked to exercise those runtimes. Product position is native-only.

**RCA.** Not a defect. Do not file a "missing WASM/Lua/JS" issue.

## Crash isolation

**Observed.** Plugin hooks run on the request task with no `catch_unwind`. `catch_unwind` in-tree is test/mesh/node-agent/soap only. `docs/configuration.md` / `docs/ci_cd.md`: shipping `release` / `ci-release` / `max-perf` set `panic = "abort"`; a panic anywhere (including a custom plugin) terminates the process. Supervisors restart. Dev/test keep `panic = "unwind"`.

**Expected for WASM/Lua guests.** Isolated guest crash. Those guests are not shipped.

**RCA.** Intentional native process model. Not a launch-readiness defect.

## Load / fail / reload (source)

Factory (`src/plugins/mod.rs`): `Ok(Some)` created, `Ok(None)` unknown name, `Err` constructor validation.

`PluginCache::try_create_plugin` (`src/plugin_cache.rs`):

- Unknown enabled name → reject generation.
- Removed security names (`oauth2_auth`, `semantic_ai_firewall`) → fatal migrate message.
- Constructor `Err` + `OptionalFailOpen` → warn and omit.
- Constructor `Err` + `FailClosed` / `KeepLastKnownGood` → reject generation (reload keeps last-known-good cache; startup has nothing to keep).

File mode (`src/modes/file.rs`): SIGHUP re-parses off-thread; Applied / Unchanged / Rejected (keep previous). Publish via atomic replace (`docs/configuration.md`).

Stateful reload exception already tracked: **#4268** (open, launch-blocker) — local rate-limit maps reset on cache rebuild. Open PR #4340. **Do not duplicate.**

File-mode validate uses `ValidationAction::FatalCount` for plugin configs, but `OptionalFailOpen` constructor failures are **warned, not collected** (`src/config/validation_pipeline.rs`). So `ferrum-edge validate` can exit 0 for a broken `stdout_logging` / `http_logging` instance that runtime then omits.

## deny_unknown_fields (source)

| Surface | Closed? |
|---|---|
| `PluginConfig` / `GatewayConfig` / `PluginTrigger` envelope | Yes (`deny_unknown_fields`) |
| jwt_auth, cors, key_auth, waf, rate_limiting, request_termination, request_transformer, … | Yes (allowlists / `reject_unknown_keys`) |
| `http_logging` | **No** — reads known keys only |
| `ws_logging` | **No** |
| `request_size_limiting` | **No** — requires `max_bytes`, ignores extras |
| `ws_message_size_limiting` | **No** |
| `prometheus_metrics` | **No** |
| `a2a_gateway` | **No** |
| `mcp_gateway` | **No** (no allowlist in `new`) |

Historical `[Plugin audit]` issues closed this class for many plugins (#2219, #2341, #2360, #2482, #2524, #2527, #2550, #2620, #2625, …). Residual gaps are the launch-readiness question; binary `validate` matrix will confirm before filing.

## Ordering (source)

Merge: globals, then scoped replacements of the same `plugin_name`, then `sort_by_key(|p| p.priority())` (stable). `priority_override` wraps the instance. Docs: equal-priority order is stable but implicit (config iteration). Size-limit and chargeback exceptions documented.

## HOLD re-verify

### #4076 — example_audit_plugin date bomb (CLOSED)

https://github.com/ferrum-edge/ferrum-edge/issues/4076 — closed by #4077.

**Observed on this SHA.** `tests/unit/plugins/example_audit_plugin_tests.rs` stamps live rows with `chrono::Utc::now()` offsets and comments the 2026-07-20 cutoff. No unfiltered `cargo test` (charter). Source-only HOLD.

**Expected.** Relative timestamps so retention DELETE cannot eat live rows as civil time moves.

**RCA.** Fixed. **HOLD — do not reopen.**

### #4038 — file-mode `proxy_id` vs `proxies[].plugins` (CLOSED)

https://github.com/ferrum-edge/ferrum-edge/issues/4038 — docs fixed by #4066.

**Observed on this SHA.** `docs/plugins.md` Scope: setting `proxy_id` alone does not attach; the proxy must list `plugins[].plugin_config_id`. `PluginCache` attachment is `proxies[].plugins` / `plugin_config_id` (e.g. `country_mmdb_plugin_is_active`). Validate of ID-only fixture is expected to still admit (runtime no-op). Runtime pair in harness.

**Expected.** Docs match cache. Validate may accept the incomplete shape.

**RCA.** Unchanged. **HOLD — do not reopen.**

## Duplicate search

Searched open issues and prior `[Plugin audit]` / launch-audit sets (#4313). Relevant already-open items in this domain:

- #4268 rate-limit state reset on plugin-cache rebuild (PR #4340)
- #4038 / #4076 CLOSED — HOLD only
- No open `[Launch readiness][PLUGINS]` issue at start of this run
- No open "http_logging/request_size_limiting silently ignore unknown keys" hit in the first search pass (rate-limited; rechecked before filing)

## Empirical matrix

See `artifacts/agent-11/harness/run_matrix.py` and `artifacts/agent-11/evidence/matrix.json` after the binary exists.

Compile and matrix results will be appended here. New `[Launch readiness][PLUGINS]` issues are filed only after Observed/Expected/RCA is proven on this SHA and a duplicate search is repeated.

## Issues

| Issue | Action |
|---|---|
| https://github.com/ferrum-edge/ferrum-edge/issues/4076 | HOLD |
| https://github.com/ferrum-edge/ferrum-edge/issues/4038 | HOLD |
| https://github.com/ferrum-edge/ferrum-edge/issues/4268 | Already tracked; referenced only |
