# Launch-readiness report: build / CLI / configuration / file mode

Domain: Build, CLI, configuration precedence, validation, file mode, reload, and migration.
Agent: Launch-Readiness Agent 01 (execution worker).
Report PR: https://github.com/ferrum-edge/ferrum-edge/pull/4078

## 1. Tested revision and environment

| Item | Value |
|------|-------|
| **Product SHA tested** | `f4b62fe7d4620d81c836d6418f2957269ac6e115` |
| Expected pin | `f4b62fe7d4620d81c836d6418f2957269ac6e115` (**match**) |
| Tree at start | clean; detached HEAD then `cursor/launch-readiness-build-cli-config-dde3` |
| OS / kernel | Linux cursor 6.12.94+ (Ubuntu Noble) |
| Arch / CPU / mem | x86_64, 4× Intel Xeon (KVM), 15 GiB RAM, 0 swap |
| rustc / cargo | 1.97.1 (8bab26f4f 2026-07-14) / 1.97.1 (c980f4866 2026-06-30) |
| protoc | libprotoc 3.21.12 (installed this run; missing at boot) |
| docker / kind / kubectl | **missing** |
| openssl / curl / python | OpenSSL 3.0.13 / curl 8.5.0 / Python 3.12.3 |
| g++ / gcc / clang / mold | 13.3.0 / 13.3.0 / 18.1.3 / 2.30.0 |
| sccache | **missing**; `.cargo/config.toml` sets `build.rustc-wrapper = "sccache"` |
| Build profile | debug then release `--bin ferrum-edge`; `RUSTFLAGS='-C debuginfo=0'`; `-j 2`; `cargo --config 'build.rustc-wrapper=""'` |
| Features | default (`crypto-ring`); no `cloud-secrets` / `fips` / `ebpf` |
| Parent `FERRUM_*` at start | **none** |
| Listeners | **127.0.0.1 only**, ports **21000–21099** |
| Debug binary | `/workspace/target/debug/ferrum-edge` (398 MiB, 2026-08-20 07:53 UTC) |
| Release binary | `/workspace/target/release/ferrum-edge` (79 MiB, 2026-08-20 08:32 UTC; fat LTO, 36m) |

### Prerequisites installed this run

```text
sudo apt-get install -y build-essential g++ libstdc++-13-dev protobuf-compiler \
  libcurl4-openssl-dev libssl-dev cmake pkg-config clang libclang-dev \
  libsasl2-dev zlib1g-dev mold
export CXX=g++ CC=gcc
```

rdkafka-sys compiled successfully after those packages (`<iostream>` was available).

## 2. Coverage matrix

**85 rows:** 83 passed, 2 failed, 0 blocked. Includes **16** negative config, **13** reload/atomicity, **3** shutdown/restart, and **J01** complete copy-paste journey.

| ID | Priority | Capability | Mode/Protocol | Method | Expected | Result | Evidence | Issue/PR |
|----|----------|------------|---------------|--------|----------|--------|----------|----------|
| B00 | P0 | debug binary present | build | stat ferrum-edge | executable exists | **passed** | `/workspace/target/debug/ferrum-edge` |  |
| B01 | P0 | missing-protoc build diagnostic | build | hide `/usr/bin/protoc`, touch proto, `cargo build --bin ferrum-edge` | actionable protoc install diagnostic; existing binary preserved | **passed** | `artifacts/agent-01/evidence/missing-protoc.err.txt` |  |
| B02 | P1 | release binary build + live smoke | build/file | `cargo build --release --bin ferrum-edge -j 2`; HTTP+TCP on 21090–21094 | 79 MiB binary; GET `/echo` 200; TCP echo; `health --live` 0 | **passed** | `release-smoke.txt` |  |
| B03 | P1 | sccache rustc-wrapper missing | build | cargo without wrapper override | documented fallback | **passed** | `artifacts/agent-01/harness/README.md` |  |
| C01 | P0 | `--help` lists documented subcommands | cli | binary `--help` | exit 0; stdout help; stderr empty; run/validate/reload/version/health/ambient-udp-preflight | **passed** | `cli-help.txt` |  |
| C02 | P0 | `run --help` flags | cli | binary `run --help` | `-s/-c/-m/-v` | **passed** | `cli-run-help.txt` |  |
| C03 | P0 | `validate --help` flags | cli | binary `validate --help` | same flags as run | **passed** | `cli-validate-help.txt` |  |
| C04 | P0 | `reload --help` | cli | binary `reload --help` | `--pid` documented | **passed** | `cli-reload-help.txt` |  |
| C05 | P0 | `version` plaintext stdout | cli | binary `version` | `ferrum-edge 0.9.0 (x86_64-unknown-linux-gnu)`; stderr empty | **passed** | `cli-version.txt` |  |
| C06 | P0 | `version --json` valid JSON | cli | binary `version --json` | `{"version","target"}`; stderr empty | **passed** | `cli-version-json.txt` |  |
| C07 | P0 | `health --help` | cli | binary `health --help` | `--port/--host/--tls/--live` | **passed** | `cli-health-help.txt` |  |
| C08 | P0 | `ambient-udp-preflight --help` | cli | binary `ambient-udp-preflight --help` | `--settings/--timeout-seconds` | **passed** | `cli-ambient-help.txt` |  |
| C09 | P0 | `migrate` is not a clap subcommand | cli | binary `migrate` | exit != 0 (mode, not subcommand) | **passed** | `cli-migrate-subcommand.txt` |  |
| C10 | P0 | invalid `--mode` rejected | cli | `run -m not-a-mode` | exit != 0 | **passed** | `cli-invalid-mode.txt` |  |
| C11 | P0 | `reload --pid` non-numeric | cli | `reload --pid not-a-pid` | clap invalid-value | **passed** | `cli-reload-invalid-pid.txt` |  |
| C12 | P1 | unknown subcommand | cli | `nosuch` | exit != 0 | **passed** | `cli-unknown-subcommand.txt` |  |
| C13 | P0 | health refused connection | cli | `health -p 1` | exit 1; no hang | **passed** | `cli-health-refused.txt` |  |
| C14 | P1 | bare `ferrum-edge` (no subcommand) | cli | no args | fail-closed `Invalid FERRUM_MODE ''` | **passed** | `cli-no-subcommand.txt` |  |
| C15 | P2 | no PID-file support | cli/reload | inventory | `--pid` or `pgrep` only | **passed** | `src/cli.rs` |  |
| V01 | P0 | validate minimal YAML HTTP+TCP | file | `validate -m file -c` | Validation passed; Proxies: 2 | **passed** | `validate-ok-yaml.txt` |  |
| V02 | P0 | validate minimal JSON HTTP+TCP | file | JSON spec | Validation passed | **passed** | `validate-ok-json.txt` |  |
| N01 | P0 | unknown field `enabled` on stream proxy | file/validate | negative fixture | fail closed | **passed** | `neg-N01.txt` | #4033 |
| N02 | P0 | duplicate proxy IDs | file/validate | negative fixture | fail closed | **passed** | `neg-N02.txt` |  |
| N03 | P0 | duplicate `listen_path` | file/validate | negative fixture | fail closed | **passed** | `neg-N03.txt` |  |
| N04 | P0 | stream port vs reserved admin port | file/validate | listen_port=21001 | Port conflict errors | **passed** | `neg-N04.txt` |  |
| N05 | P1 | invalid `backend_scheme` | file/validate | `ftp` | fail closed | **passed** | `neg-N05.txt` |  |
| N06 | P1 | missing `backend_host` | file/validate | omitted field | fail closed | **passed** | `neg-N06.txt` |  |
| N07 | P1 | empty proxy id | file/validate | `id: ""` | fail closed | **passed** | `neg-N07.txt` |  |
| N08 | P0 | malformed YAML | file/validate | torn YAML | fail closed | **passed** | `neg-N08.txt` |  |
| N09 | P0 | malformed JSON | file/validate | torn JSON | fail closed | **passed** | `neg-N09.txt` |  |
| N10 | P1 | missing `version` | file/validate | no version | fail closed | **passed** | `neg-N10.txt` |  |
| N11 | P1 | missing spec file | file/validate | nonexistent path | fail closed | **passed** | `neg-N11.txt` |  |
| N12 | P1 | stream `listen_port: 0` | file/validate | port 0 | fail closed | **passed** | `neg-N12.txt` |  |
| N13 | P1 | Unicode proxy id rejected | file/validate | `路由-α` | ID charset fail-closed | **passed** | `neg-N13.txt` |  |
| N14 | P1 | stream proxy + `listen_path` | file/validate | both fields | fail closed | **passed** | `neg-N14.txt` |  |
| N15 | P1 | empty `backend_host` | file/validate | `""` | fail closed | **passed** | `neg-N15.txt` |  |
| N16 | P1 | duplicate stream `listen_port` | file/validate | two TCP on 21003 | fail closed | **passed** | `neg-N16.txt` |  |
| D01 | P0 | README file-mode example | docs/file | extract + validate | exit 0 | **passed** | `docs-readme.yaml.txt` |  |
| D02 | P0 | `docs/configuration.md` file-mode YAML | docs/file | extract + validate | exit 0 | **passed** | `docs-configuration.yaml.txt` |  |
| D03 | P0 | `docs/tcp_udp_proxy.md` + `enabled: true` | docs/file | copy-paste + validate | should validate | **failed** | `docs-tcp-udp.yaml.txt` | [#4033](https://github.com/ferrum-edge/ferrum-edge/issues/4033) |
| D04 | P1 | same TCP examples minus `enabled` | docs/file | + `plugin_configs: []` | validate | **passed** | `docs-tcp-udp-cleaned.yaml.txt` |  |
| D05 | P0 | README `tests/config.yaml` | docs/file | validate | exit 0 | **passed** | `docs-tests-config.yaml.txt` |  |
| D06 | P1 | `openapi_validator` without `api_spec_id` | docs/file | correct `path_template` schema | validate 0 | **passed** | `docs-openapi-no-spec-id-correct.txt` | [#4037](https://github.com/ferrum-edge/ferrum-edge/issues/4037) |
| D07 | P1 | `proxy_id` only (no `proxies[].plugins`) | docs/file | validate | admitted | **passed** | `docs-plugin-proxy-id-only.txt` | [#4038](https://github.com/ferrum-edge/ferrum-edge/issues/4038) |
| Z01 | P0 | `FERRUM_PROXY_HTTP_PORT=0` disables HTTP proxy | file | run | 21000/8000 not bound | **passed** | `port0-proxy.txt` |  |
| Z02 | P0 | port 0 excluded from reserved ports | file/validate | stream on 21000 while HTTP=0 | validate 0 | **passed** | `port0-reserved.txt` |  |
| Z03 | P0 | `FERRUM_ADMIN_HTTP_PORT=0` disables admin HTTP | file | run | 21041/9000 not bound | **passed** | `port0-admin.txt` |  |
| Z04 | P1 | CP gRPC `:0` not reserved | file/validate | `127.0.0.1:0` | validate 0 | **passed** | `cp-port0-validate.txt` |  |
| L01 | P0 | HTTP route on loopback | file/http | GET `/echo/hello` | 200 via 127.0.0.1:21000 | **passed** | `live-http.txt` |  |
| L02 | P0 | TCP stream on loopback | file/tcp | TCP echo | `tcp-ping` echoed on 21003 | **passed** | `live-tcp.txt` |  |
| J01 | P0 | copy-paste journey | file/http+tcp | validate → run → GET + TCP | 200 + echo | **passed** | `journey.txt` |  |
| P01 | P0 | CLI > env > conf ports/mode/spec | file | conflicting `-m/-c` vs env vs conf | env ports 21000/21001; conf 21050/21051 unused; File mode | **passed** | `precedence.txt` |  |
| P02 | P0 | validate reports CLI mode | file/validate | `-m file` vs env database | `Mode: File` | **passed** | `precedence-validate.txt` |  |
| H01 | P0 | health CLI readiness plaintext | file/admin | `health -p 21031` | exit 0 | **passed** | `health-ready.txt` |  |
| H02 | P0 | health CLI `--live` | file/admin | `health --live` | exit 0 | **passed** | `health-live.txt` |  |
| H03 | P0 | GET `/live` unauthenticated | file/admin | GET | 200 minimal | **passed** | `admin-live.json` |  |
| H04 | P0 | GET `/health` unauth coarse | file/admin | GET no JWT | keys `status`,`ready` only | **passed** | `admin-health-unauth.txt` |  |
| H05 | P0 | GET `/health` auth detail | file/admin | Bearer JWT | richer body; `config_rejected` visible after bad reload | **passed** | `admin-health-auth.txt` |  |
| H06 | P1 | GET `/metrics` unauth 401 | file/admin | GET | 401 | **passed** | `admin-metrics-unauth.txt` |  |
| H07 | P1 | health TLS `--tls-no-verify` | file/admin-tls | self-signed | exit 0 | **passed** | `health-tls-no-verify.txt` |  |
| H08 | P1 | health TLS verify rejects self-signed | file/admin-tls | `--tls` | exit 1 | **passed** | `health-tls-verify-fail.txt` |  |
| H09 | P1 | health `--live` over TLS | file/admin-tls | `--live --tls --tls-no-verify` | exit 0 | **passed** | `health-tls-live.txt` |  |
| S01 | P0 | SIGTERM stops accept and exits | file | SIGTERM | port freed | **passed** | `sigterm.txt` |  |
| S02 | P0 | immediate rebind after SIGTERM | file | restart same ports | admin+proxy accept | **passed** | `sigterm-rebind.txt` |  |
| S03 | P0 | SIGINT graceful stop | file | SIGINT | exits; ports released | **passed** | `sigint.txt` |  |
| R01 | P0 | SIGHUP add route (atomic rename + `reload --pid`) | file/reload | rewrite + CLI reload | `/v2` 200; `/echo` 200 | **passed** | `reload-add.txt` |  |
| R02 | P0 | invalid SIGHUP keeps last-good | file/reload | torn YAML | `/echo`+`/v2` 200; auth `/health` `degraded` + `config_rejected: true` | **passed** | `reload-invalid.txt` |  |
| R03 | P0 | repair + SIGHUP new generation | file/reload | add `/v3` drop `/v2` | `/v3` 200; `/v2` gone | **passed** | `reload-repair.txt` |  |
| R04 | P1 | rapid consecutive reloads | file/reload | 5 SIGHUPs | final `/r4` 200 | **passed** | `reload-rapid.txt` |  |
| R05 | P1 | `reload --pid` unrelated PID 1 | cli/reload | `--pid 1` | exit != 0 | **passed** | `reload-pid-unrelated.txt` |  |
| R06 | P1 | `reload --pid` missing PID | cli/reload | `--pid 999999` | exit != 0 | **passed** | `reload-pid-missing.txt` |  |
| R07 | P1 | `reload --pid 0` process-group SIGHUP | cli/reload | isolated `setsid` | should reject | **failed** | `reload-pid-zero-isolated.txt` | [#4079](https://github.com/ferrum-edge/ferrum-edge/issues/4079) |
| R08 | P1 | deleted spec + SIGHUP | file/reload | unlink + SIGHUP | last-good 200 | **passed** | `reload-deleted.txt` |  |
| R09 | P1 | reload during graceful shutdown | file/reload | SIGTERM then reload | process exits | **passed** | `reload-during-shutdown.txt` |  |
| R10 | P1 | partial in-place write + SIGHUP | file/reload | truncate YAML | last-good 200 | **passed** | `reload-partial.txt` |  |
| R11 | P1 | permission loss + SIGHUP | file/reload | chmod 000 | last-good 200 | **passed** | `reload-chmod.txt` |  |
| R12 | P1 | symlink swap reload | file/reload | replace with symlink | `/link` 200 | **passed** | `reload-symlink.txt` |  |
| R13 | P2 | large valid config (80 proxies) | file/reload | SIGHUP | `/bulk79` 200 | **passed** | `reload-large.txt` |  |
| M01 | P0 | migrate config already at v1 | migrate | `ACTION=config` | exit 0; no rewrite | **passed** | `migrate-current.txt` |  |
| M02 | P1 | migrate config idempotent | migrate | run twice | exit 0 | **passed** | `migrate-idempotent.txt` |  |
| M03 | P1 | migrate config missing version | migrate | no version | exit != 0 | **passed** | `migrate-missing-version.txt` |  |
| M04 | P1 | migrate config malformed | migrate | broken YAML | exit != 0 | **passed** | `migrate-malformed.txt` |  |
| M05 | P1 | migrate config read-only current file | migrate | chmod 444 | exit 0 (no write) | **passed** | `migrate-readonly.txt` |  |
| M06 | P1 | bare binary + `FERRUM_MODE=migrate` | migrate | no subcommand | exit 0 | **passed** | `migrate-bare.txt` |  |
| M07 | P0 | migrate does not print secrets | migrate | keyauth consumer | secret absent from stdout/stderr | **passed** | `migrate-secret.txt` |  |

Evidence paths are under `artifacts/agent-01/evidence/` unless noted.

## 3. Commands and reusable local fixture instructions

See `artifacts/agent-01/harness/README.md`.

```bash
export CXX=g++ CC=gcc RUSTFLAGS='-C debuginfo=0'
# sccache is configured but may be missing
cargo --config 'build.rustc-wrapper=""' build --bin ferrum-edge -j 1
export FERRUM_EDGE_BIN=/workspace/target/debug/ferrum-edge
python3 artifacts/agent-01/harness/run_matrix.py
# remaining rows after R06 (do not run reload --pid 0 in-process):
python3 artifacts/agent-01/harness/finish_rows.py
```

Fixtures: `artifacts/agent-01/fixtures/minimal-http-tcp.yaml` and `.json`.
Do **not** set `auth_mode: none` (only `single`/`multi`; omit to default `single`).
`GatewayConfig` requires `plugin_configs` (use `[]`).
Bind only `127.0.0.1` on 21000–21099. No public backends.

Copy-paste journey (J01):

```bash
# from a clean checkout after building the binary
cat > /tmp/journey.yaml <<'YAML'
version: "1"
plugin_configs: []
proxies:
  - id: http-echo
    listen_path: /echo
    backend_scheme: http
    backend_host: 127.0.0.1
    backend_port: 21002
    strip_listen_path: true
  - id: tcp-echo
    listen_port: 21003
    backend_scheme: tcp
    backend_host: 127.0.0.1
    backend_port: 21004
YAML
# start loopback HTTP and TCP echo backends on 21002/21004
FERRUM_PROXY_BIND_ADDRESS=127.0.0.1 FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 \
FERRUM_STREAM_PROXY_BIND_ADDRESS=127.0.0.1 \
FERRUM_PROXY_HTTP_PORT=21000 FERRUM_ADMIN_HTTP_PORT=21001 \
FERRUM_PROXY_HTTPS_PORT=0 FERRUM_ADMIN_HTTPS_PORT=0 \
FERRUM_POOL_WARMUP_ENABLED=false \
./target/debug/ferrum-edge validate -m file -c /tmp/journey.yaml
./target/debug/ferrum-edge run -m file -c /tmp/journey.yaml
# GET http://127.0.0.1:21000/echo/hello  → 200
# TCP 127.0.0.1:21003 echoes payload
```

## 4. Passed / failed / blocked / not-tested

| Status | Count | Notes |
|--------|-------|-------|
| **passed** | 83 | All P0 runtime/startup/reload/health/shutdown/migrate rows except docs #4033; release smoke included |
| **failed** | 2 | D03 (`enabled: true` on main docs); R07 (`reload --pid 0`) |
| **blocked** | 0 | Release binary finished (36m fat LTO) |
| **not-tested** | listed in §8 | cloud secrets, docker/kind, privileged Ambient UDP, PR #4066 worktree runtime |

P0/P1 startup and reload claims were executed against the **real debug binary**, not code-review-only.

## 5. Issue / PR URLs published

| URL | Action |
|-----|--------|
| https://github.com/ferrum-edge/ferrum-edge/issues/4033#issuecomment-5353180878 | Binary confirm; RCA unchanged |
| https://github.com/ferrum-edge/ferrum-edge/issues/4037#issuecomment-5353181037 | Binary confirm; file-mode admits without `api_spec_id` |
| https://github.com/ferrum-edge/ferrum-edge/issues/4038#issuecomment-5353181175 | Validate admits `proxy_id` only; attachment still `proxies[].plugins` |
| https://github.com/ferrum-edge/ferrum-edge/issues/4079 | **New** — `reload --pid 0` → `kill -HUP 0` |
| https://github.com/ferrum-edge/ferrum-edge/pull/4066 | Unmerged docs-only fix; **not treated as a fix on main** |
| https://github.com/ferrum-edge/ferrum-edge/pull/4078 | This artifacts-only report |

No production code was pushed.

## 6. Confirmed RCAs and unresolved hypotheses

### Confirmed

1. **#4033** — `Proxy` is `#[serde(deny_unknown_fields)]` and has no `enabled`. Main `docs/tcp_udp_proxy.md` still copy-pastes `enabled: true`. Removing the field (and adding `plugin_configs: []`) validates. PR #4066 would fix docs only.
2. **#4037** — `api_spec_id` is an Admin API precondition (`validate_openapi_validator_precondition`). File mode admits a proxy-scoped `openapi_validator` with hand-authored `operations` and no `api_spec_id` once keys are `path_template` / `request_required`. Docs L305 on main still state the Admin rule as universal.
3. **#4038** — File-mode validate accepts `scope: proxy` + `proxy_id` without `proxies[].plugins`. Runtime attachment is the association list (`PluginCache`), matching the original RCA. Docs Scope prose on main still implies `proxy_id` alone applies the plugin.
4. **#4079** — `execute_reload` interpolates `--pid` into `kill -HUP`. POSIX `kill` treats `0` as “this process group”. Isolated `setsid ferrum-edge reload --pid 0` exits 129 (SIGHUP).
5. **Config migration chain is empty.** `CURRENT_CONFIG_VERSION` is `"1"`. `migrate config` on a current file is a no-op (no backup). Missing version / malformed files fail closed. No silent data loss observed.
6. **No PID file.** Reload is `--pid` or `pgrep -x ferrum-edge`.
7. **Precedence** — CLI `-m file` + `-c spec` beat env `FERRUM_MODE=database` and conf ports; logs show `environment variable overrides ferrum.conf`. File-mode inference does not override an explicit env/conf mode (`docs/cli.md` Mode Inference).
8. **Invalid SIGHUP** — last-good routes stay live; authenticated `/health` returns `status: degraded` and `config_rejected: true`.
9. **Missing protoc** — `prost-build` error names `protoc`, suggests `PROTOC`, `apt-get install protobuf-compiler`, and protobuf releases. Actionable. Existing debug binary was not overwritten.

### Unresolved / out of scope

- PR #4066 head not checked out in a second worktree (diff reviewed via GitHub API; docs-only, +7/−7).
- Runtime webhook re-proof of #4038 (validate + source confirmed).
- `auth_mode: none` is invalid (`single`/`multi` only). Not a product bug; easy fixture footgun.
- `GatewayConfig.plugin_configs` is required (no `#[serde(default)]`). Doc fragments that omit it fail before the intended field error.

## 7. Documentation / example discrepancies

| Document | Discrepancy | Launch impact |
|----------|-------------|---------------|
| `docs/tcp_udp_proxy.md` | Four File Mode examples include `enabled: true` | Copy-paste fail-closed (#4033). `docs/configuration.md` stream examples are already correct. |
| `docs/openapi_validator.md` L305 | Claims `api_spec_id` required for direct plugins | False for file mode (#4037). |
| `docs/plugins.md` Scope | `proxy_id` described as sufficient | File mode needs `proxies[].plugins` (#4038). |
| `docs/cli.md` | “A subcommand is required” | Bare `ferrum-edge` enters the serving path; without mode it errors `Invalid FERRUM_MODE ''`. `docs/migrations.md` documents the bare binary with `FERRUM_MODE=migrate` (works). |
| `docs/cli.md` subcommand table | No `migrate` subcommand | Correct vs clap; easy to miss that migrate is a mode. |
| File Mode YAML fragments | Often omit `version` / `plugin_configs` | Incomplete snippets fail validate; mark as partial. |
| README getting-started | `tests/config.yaml` uses public `httpbin.org` | Validates; **do not** use for loopback launch tests. |
| PR #4066 | Docs-only fixes for #4033/#4037/#4038 | **Not merged** as of this SHA. |

## 8. Untested third-party-account-only paths

- `_VAULT` / `_AWS` / `_AZURE` / `_GCP` suffixes (`cloud-secrets` not in default features). Default binary **fails closed** on a non-empty cloud suffix (documented).
- Docker / GHCR / kind / kubectl (tools missing).
- Privileged Ambient UDP preflight against a real node / host `/proc` (help only).
- Database/CP/DP live modes (charter is file-mode/CLI/build).
- Windows non-Unix `reload` path (source returns a fixed error; this host is Linux).

## 9. Confidence and verdict

**Confidence: high** on file-mode startup, validation, precedence, port-0, health (plain + TLS), SIGHUP atomicity, SIGTERM/SIGINT, and migrate-config. Those ran on the real debug binary at `f4b62fe7d4620d81c836d6418f2957269ac6e115`. Release binary (79 MiB) also validated and served HTTP+TCP on loopback.

**Verdict: Ready with explicit risks**

- Runtime file-mode HTTP + TCP, validate, reload fail-closed, health gating, and shutdown/rebind worked on loopback (debug + release smoke).
- Main-branch docs still ship a failing TCP copy-paste (#4033). That is a launch usability defect, not a silent data-plane failure.
- `reload --pid 0` is an operator footgun (#4079), Medium.
- Container/K8s paths were not completed here (docker/kind/kubectl missing).

## 10. Three most important follow-ups by launch risk

1. **Merge or land the #4066 docs fixes** so `docs/tcp_udp_proxy.md` copy-paste validates on main. Highest operator-onboarding risk in this domain.
2. **Reject `reload --pid 0` (and other special PIDs)** before calling `kill` (#4079).
3. **Align CLI docs** (`subcommand required` vs bare `ferrum-edge` + `FERRUM_MODE=migrate`) and optionally add a `migrate` clap subcommand so `ferrum-edge migrate` is not an unknown-command surprise.

---

### Hot-zone re-verify (this SHA, not #4066)

| Issue | Main still broken? | Binary result |
|-------|--------------------|---------------|
| #4033 `enabled: true` | Yes | validate exit 1, unknown field `enabled` |
| #4037 `api_spec_id` | Docs yes / runtime no | file-mode validate **passes** without `api_spec_id` |
| #4038 `proxy_id` vs `plugins[]` | Docs yes | validate **passes** without association; attachment still association-based |
| PR #4066 | Unmerged, base = this SHA | Docs-only; would fix the three doc sentences |
