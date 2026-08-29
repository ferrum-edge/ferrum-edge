# Launch-readiness report: build / CLI / configuration / file mode

Domain: Build, CLI, configuration precedence, validation, file mode, reload, and migration.
Agent: Launch-Readiness Agent 01 (execution worker), retry after closed drafts #4078 and #4260.
This is a **new artifacts tree**. Do not treat #4260 as current-main evidence.

## 1. Tested revision and environment

| Item | Value |
|------|-------|
| **Product SHA tested** | `b96cfaadd41a676d39a409d47b48e0b0588fa86e` |
| `origin/main` at start | `b96cfaadd41a676d39a409d47b48e0b0588fa86e` (**match**; latest fetch 2026-08-29) |
| Tree at start | isolated branch `cursor/launch-readiness-build-cli-config-a782` from `origin/main` |
| OS / kernel | Linux cursor 6.12.94+ (Ubuntu Noble) |
| Arch / CPU / mem | x86_64, 4×, 15 GiB RAM, 0 swap |
| rustc / cargo | 1.98.0 (88d9e12ae 2026-08-18) / 1.98.0 (797e8a9bc 2026-08-05) |
| protoc | libprotoc 3.21.12 (installed this run) |
| docker / kind / kubectl | **missing** |
| openssl / curl / python | OpenSSL 3.0.13 / curl 8.5.0 / Python 3.12.3 |
| g++ / gcc / clang / mold | 13.3.0 / 13.3.0 / 18.1.3 / 2.30.0 |
| sccache | **missing**; `.cargo/config.toml` sets `build.rustc-wrapper = "sccache"` |
| Build profile | debug `--bin ferrum-edge`; `RUSTFLAGS='-C debuginfo=0 -C strip=debuginfo'`; `-j 1`; `cargo --config 'build.rustc-wrapper=""'` |
| Features | default (`crypto-ring`); no `cloud-secrets` / `fips` / `ebpf` |
| Parent `FERRUM_*` at start | **none** |
| Listeners | **127.0.0.1 only**, ports **21000–21099** |
| Debug binary | `/workspace/target/debug/ferrum-edge` (383 MiB / 400993400 bytes, 2026-08-29 01:30 UTC); `ferrum-edge 0.9.0 (x86_64-unknown-linux-gnu)` |
| Release binary | **blocked** — 15 GiB RAM exhausted during LTO of `ferrum_edge` (`-C linker-plugin-lto -C codegen-units=1`). No `target/release/ferrum-edge`. Charter: use the debug binary already built. |

### Prerequisites installed this run

```text
sudo apt-get update && sudo apt-get install -y build-essential g++ libstdc++-13-dev \
  protobuf-compiler libcurl4-openssl-dev libssl-dev cmake pkg-config clang libclang-dev \
  libsasl2-dev zlib1g-dev mold
export CXX=g++ CC=gcc
```

rdkafka-sys compiled successfully (`<iostream>` available). Debug build finished in 14m 34s.

## 2. Coverage matrix

**85 rows** (final). Includes **16** negative config, **13** reload/atomicity, **3** shutdown/restart, and **J01** complete copy-paste journey.

All P0/P1 startup, validate, live HTTP/TCP, precedence, health, reload, shutdown, and migrate-config rows ran against the **real debug `ferrum-edge` binary**.

| ID | Priority | Capability | Mode/Protocol | Method | Expected | Result | Evidence | Issue/PR |
|----|----------|------------|---------------|--------|----------|--------|----------|----------|
| B00 | P0 | debug binary present | build | stat ferrum-edge | executable exists | **passed** | `/workspace/target/debug/ferrum-edge` |  |
| B01 | P0 | missing-protoc build diagnostic | build | hide protoc, invoke compiled build.rs | actionable protoc install diagnostic; existing debug binary preserved | **failed** | `missing-protoc-buildrs.txt` | [#4361](https://github.com/ferrum-edge/ferrum-edge/issues/4361) |
| B02 | P1 | release binary build | build | cargo build --release --bin ferrum-edge -j 1 | target/release/ferrum-edge executable | **blocked** | `release-smoke.txt` |  |
| B03 | P1 | sccache rustc-wrapper documented fallback | build | inspect .cargo/config.toml + PATH | wrapper may be missing; override documented and used | **passed** | `sccache-wrapper.txt` |  |
| C01 | P0 | --help lists documented subcommands | cli | binary --help | exit 0, stdout help, stderr empty, run/validate/reload/version/health/ambient-udp-preflight present | **passed** | `cli-help.txt` |  |
| C02 | P0 | run --help flags | cli | binary run --help | exit 0; -s/-c/-m/-v documented | **passed** | `cli-run-help.txt` |  |
| C03 | P0 | validate --help flags | cli | binary validate --help | exit 0; same flags as run | **passed** | `cli-validate-help.txt` |  |
| C04 | P0 | reload --help | cli | binary reload --help | exit 0; --pid documented | **passed** | `cli-reload-help.txt` |  |
| C05 | P0 | version plaintext stdout | cli | binary version | exit 0; 'ferrum-edge X.Y.Z (target)' on stdout; stderr empty | **passed** | `cli-version.txt` |  |
| C06 | P0 | version --json is valid JSON | cli | binary version --json | exit 0; JSON object with version+target; stderr empty | **passed** | `cli-version-json.txt` |  |
| C07 | P0 | health --help | cli | binary health --help | exit 0; --port/--host/--tls/--live documented | **passed** | `cli-health-help.txt` |  |
| C08 | P0 | ambient-udp-preflight --help | cli | binary ambient-udp-preflight --help | exit 0; --settings/--timeout-seconds documented | **passed** | `cli-ambient-help.txt` |  |
| C09 | P0 | migrate is not a clap subcommand | cli | binary migrate | exit != 0 with invalid-subcommand diagnostic (docs/cli.md: subcommand required; migrate is a mode) | **passed** | `cli-migrate-subcommand.txt` |  |
| C10 | P0 | invalid --mode rejected | cli | binary run -m not-a-mode | exit != 0; diagnostic names allowed modes | **passed** | `cli-invalid-mode.txt` |  |
| C11 | P0 | reload --pid non-numeric | cli | binary reload --pid not-a-pid | exit != 0; clap invalid-value on stderr | **passed** | `cli-reload-invalid-pid.txt` |  |
| C12 | P1 | unknown subcommand | cli | binary nosuch | exit != 0 | **passed** | `cli-unknown-subcommand.txt` |  |
| C13 | P0 | health refused connection | cli | binary health -p 1 | exit 1; connection error; no hang | **passed** | `cli-health-refused.txt` |  |
| C14 | P1 | bare ferrum-edge (no subcommand) | cli | binary with no args (8s timeout) | docs/cli.md says subcommand required; migrations.md uses bare binary. Fail-closed or start. | **passed** | `cli-no-subcommand.txt` |  |
| C15 | P2 | no PID-file support | cli/reload | inventory src/cli.rs | --pid or pgrep only; no PID file | **passed** | `cli-no-pid-file.txt` |  |
| V01 | P0 | validate minimal YAML HTTP+TCP | file/http+tcp | binary validate -m file -c | exit 0; Validation passed; Proxies: 2 | **passed** | `validate-ok-yaml.txt` |  |
| V02 | P0 | validate minimal JSON HTTP+TCP | file/http+tcp | binary validate JSON spec | exit 0; Validation passed | **passed** | `validate-ok-json.txt` |  |
| N01 | P0 | unknown field enabled on stream proxy | file/validate | binary validate negative fixture | fail closed, no Validation passed | **passed** | `neg-N01.txt` |  |
| N02 | P0 | duplicate proxy IDs | file/validate | binary validate negative fixture | fail closed, no Validation passed | **passed** | `neg-N02.txt` |  |
| N03 | P0 | duplicate listen_path | file/validate | binary validate negative fixture | fail closed, no Validation passed | **passed** | `neg-N03.txt` |  |
| N04 | P0 | stream listen_port conflicts reserved admin port | file/validate | binary validate negative fixture | fail closed, no Validation passed | **passed** | `neg-N04.txt` |  |
| N05 | P1 | invalid backend_scheme | file/validate | binary validate negative fixture | fail closed, no Validation passed | **passed** | `neg-N05.txt` |  |
| N06 | P1 | missing required backend_host | file/validate | binary validate negative fixture | fail closed, no Validation passed | **passed** | `neg-N06.txt` |  |
| N07 | P1 | empty proxy id | file/validate | binary validate negative fixture | fail closed, no Validation passed | **passed** | `neg-N07.txt` |  |
| N08 | P0 | malformed YAML | file/validate | binary validate negative fixture | fail closed, no Validation passed | **passed** | `neg-N08.txt` |  |
| N09 | P0 | malformed JSON | file/validate | binary validate negative fixture | fail closed, no Validation passed | **passed** | `neg-N09.txt` |  |
| N10 | P1 | missing version field | file/validate | binary validate negative fixture | fail closed, no Validation passed | **passed** | `neg-N10.txt` |  |
| N11 | P1 | invalid path missing file | file/validate | binary validate negative fixture | fail closed, no Validation passed | **passed** | `neg-N11.txt` |  |
| N12 | P1 | boundary listen_port 0 on stream | file/validate | binary validate negative fixture | fail closed, no Validation passed | **passed** | `neg-N12.txt` |  |
| N13 | P1 | Unicode proxy id rejected by ID charset | file/validate | binary validate negative fixture | fail closed, no Validation passed | **passed** | `neg-N13.txt` |  |
| N14 | P1 | stream proxy must not set listen_path | file/validate | binary validate negative fixture | fail closed, no Validation passed | **passed** | `neg-N14.txt` |  |
| N15 | P1 | empty string backend_host | file/validate | binary validate negative fixture | fail closed, no Validation passed | **passed** | `neg-N15.txt` |  |
| N16 | P1 | duplicate listen_port stream proxies | file/validate | binary validate negative fixture | fail closed, no Validation passed | **passed** | `neg-N16.txt` |  |
| D01 | P0 | README file-mode example validates | docs/file | extract README YAML + validate | exit 0 or documented partial | **passed** | `docs-readme.yaml.txt` |  |
| D02 | P0 | docs/configuration.md file-mode YAML validates | docs/file | extract configuration.md example | exit 0 | **passed** | `docs-configuration.yaml.txt` |  |
| D03 | P0 | docs/tcp_udp_proxy.md File Mode examples (no enabled: true) | docs/file | confirm no enabled field; wrap version/plugin_configs; validate | doc has no enabled:; wrapped copy-paste validates (re-verify #4033/#4066) | **passed** | `docs-tcp-udp.yaml.txt` | [#4033](https://github.com/ferrum-edge/ferrum-edge/issues/4033) |
| D04 | P1 | tcp_udp_proxy.md documents missing enabled + wrapped examples validate | docs/file | doc prose + same YAML minus any enabled line | prose says stream proxies have no enabled field; validate passes | **passed** | `docs-tcp-udp-cleaned.yaml.txt` |  |
| D05 | P0 | README getting-started tests/config.yaml validates | docs/file | validate tests/config.yaml | exit 0 | **passed** | `docs-tests-config.yaml.txt` |  |
| D06 | P1 | openapi_validator file-mode without api_spec_id | docs/file | hand-authored operations (path_template+path_regex), no api_spec_id | validate passes; docs distinguish Admin vs file-mode (#4037 hold after #4066) | **passed** | `docs-openapi-no-spec-id.txt` | [#4037](https://github.com/ferrum-edge/ferrum-edge/issues/4037) |
| D07 | P1 | proxy-scoped plugin with proxy_id only validates | docs/file | scope=proxy + proxy_id, no proxies[].plugins | validate accepts; docs now say proxy_id alone does not attach (#4038 hold after #4066) | **passed** | `docs-plugin-proxy-id-only.txt` | [#4038](https://github.com/ferrum-edge/ferrum-edge/issues/4038) |
| Z01 | P0 | FERRUM_PROXY_HTTP_PORT=0 disables plaintext proxy | file | binary run port 0 | admin up; 21000/8000 not listening; TCP stream still works | **passed** | `port0-proxy.txt` |  |
| Z02 | P0 | port 0 excluded from reserved_gateway_ports | file/validate | stream listen_port=21000 while proxy HTTP=0 | validate passes (21000 not reserved) | **passed** | `port0-reserved.txt` |  |
| Z03 | P0 | FERRUM_ADMIN_HTTP_PORT=0 disables plaintext admin | file | binary run admin port 0 | proxy may bind; admin 21041/9000 not listening | **passed** | `port0-admin.txt` |  |
| Z04 | P1 | CP gRPC listen :0 excluded from reserved ports (file validate) | file/validate | FERRUM_CP_GRPC_LISTEN_ADDR=127.0.0.1:0 + stream on 21003 | validate still passes | **passed** | `cp-port0-validate.txt` |  |
| L01 | P0 | file-mode HTTP route on loopback | file/http | binary run + GET /echo/hello | HTTP 200 via 127.0.0.1:21000 | **passed** | `live-http.txt` |  |
| L02 | P0 | file-mode TCP stream route on loopback | file/tcp | binary run + TCP echo | payload echoed via 127.0.0.1:21003 | **passed** | `live-tcp.txt` |  |
| J01 | P0 | copy-paste journey checkout→validate→traffic | file/http+tcp | validate -m file -c; run -m file -c; GET /echo; TCP echo | validate 0, HTTP 200, TCP echo on loopback 21000/21003 | **passed** | `journey.txt` |  |
| P01 | P0 | CLI > env > conf for mode/spec/ports | file | conflicting -m/-c vs env vs ferrum.conf | serves CLI spec on env ports; conf ports unused; database mode from env ignored | **passed** | `precedence.txt` |  |
| P02 | P0 | validate reports CLI-winning mode | file/validate | validate -m file vs env database | Mode: File and Validation passed | **passed** | `precedence-validate.txt` |  |
| H01 | P0 | health CLI readiness plaintext | file/admin | binary health -p 21031 | exit 0 | **passed** | `health-ready.txt` |  |
| H02 | P0 | health CLI --live | file/admin | binary health --live | exit 0 | **passed** | `health-live.txt` |  |
| H03 | P0 | GET /live unauthenticated minimal | file/admin | GET /live | 200 {status:ok} only | **passed** | `admin-live.json` |  |
| H04 | P0 | GET /health unauthenticated is coarse | file/admin | GET /health no JWT | 200 with status+ready only; no full diagnostics | **passed** | `admin-health-unauth.txt` |  |
| H05 | P0 | GET /health authenticated detail | file/admin | GET /health + JWT | 200 with richer diagnostics than unauth | **passed** | `admin-health-auth.txt` |  |
| H06 | P1 | GET /metrics unauthenticated 401 | file/admin | GET /metrics | 401 | **passed** | `admin-metrics-unauth.txt` |  |
| H07 | P1 | health --tls --tls-no-verify against self-signed | file/admin-tls | binary health --tls --tls-no-verify | exit 0 | **passed** | `health-tls-no-verify.txt` |  |
| H08 | P1 | health --tls rejects invalid/self-signed cert | file/admin-tls | binary health --tls (verify on) | exit 1 | **passed** | `health-tls-verify-fail.txt` |  |
| H09 | P1 | health --live over TLS | file/admin-tls | health --live --tls --tls-no-verify | exit 0 | **passed** | `health-tls-live.txt` |  |
| S01 | P0 | SIGTERM stops accept and exits | file | SIGTERM running gateway | process exits; port free for rebind | **passed** | `sigterm.txt` |  |
| S02 | P0 | immediate rebind after SIGTERM | file | restart same ports | admin+proxy accept again | **passed** | `sigterm-rebind.txt` |  |
| S03 | P0 | SIGINT graceful stop | file | SIGINT | exits and releases ports | **passed** | `sigint.txt` |  |
| R01 | P0 | SIGHUP add route via atomic rename + reload --pid | file/reload | rewrite spec, ferrum-edge reload --pid | exit 0; /v2 becomes 200; /echo still works | **passed** | `reload-add.txt` |  |
| R02 | P0 | invalid SIGHUP keeps last-good generation | file/reload | write malformed YAML + SIGHUP | process alive; /echo and /v2 still 200; auth /health reports rejected/degraded | **passed** | `reload-invalid.txt` |  |
| R03 | P0 | repair + SIGHUP applies new generation | file/reload | write valid spec missing /v2 adding /v3 | /v3=200; /v2 gone (404/no route); process healthy | **passed** | `reload-repair.txt` |  |
| R04 | P1 | rapid consecutive reloads | file/reload | 5 SIGHUPs | final generation live; process healthy | **passed** | `reload-rapid.txt` |  |
| R05 | P1 | reload --pid unrelated PID 1 | cli/reload | reload --pid 1 | non-zero (EPERM/ESRCH) or documented failure | **passed** | `reload-pid-unrelated.txt` |  |
| R06 | P1 | reload --pid missing PID | cli/reload | reload --pid 999999 | exit != 0 | **passed** | `reload-pid-missing.txt` |  |
| R07 | P1 | reload --pid 0 rejected (re-verify #4084) | cli/reload | setsid --wait ferrum-edge reload --pid 0 | exit != 0 and != 129; clap/range or unix_reload_pid_t rejects 0; no process-group SIGHUP | **passed** | `reload-pid-zero-isolated.txt` | [#4079](https://github.com/ferrum-edge/ferrum-edge/issues/4079) |
| R08 | P1 | SIGHUP after deleted spec keeps last-good | file/reload | unlink spec + SIGHUP | process + old routes stay healthy | **passed** | `reload-deleted.txt` |  |
| R09 | P1 | reload during graceful shutdown | file/reload | SIGTERM then reload --pid | no crash loop; process exits | **passed** | `reload-during-shutdown.txt` |  |
| R10 | P1 | partial in-place write + SIGHUP | file/reload | truncate YAML then SIGHUP | reject torn candidate; /echo stays 200 | **passed** | `reload-partial.txt` |  |
| R11 | P1 | permission loss on spec + SIGHUP | file/reload | chmod 000 + SIGHUP | last-good kept | **passed** | `reload-chmod.txt` |  |
| R12 | P1 | symlink swap reload | file/reload | replace spec with symlink | new generation from symlink target | **passed** | `reload-symlink.txt` |  |
| R13 | P2 | large valid config reload (80 proxies) | file/reload | SIGHUP 80-route spec | /bulk79=200 | **passed** | `reload-large.txt` |  |
| M01 | P0 | migrate config already-current version 1 | migrate/config | FERRUM_MODE=migrate ACTION=config on v1 | exit 0; no backup (already current); no secret leak | **passed** | `migrate-current.txt` |  |
| M02 | P0 | migrate config idempotent | migrate/config | run twice | second run exit 0 | **passed** | `migrate-idempotent.txt` |  |
| M03 | P1 | migrate config missing version | migrate/config | file without version | exit != 0; no silent rewrite | **passed** | `migrate-missing-version.txt` |  |
| M04 | P1 | migrate config malformed | migrate/config | broken YAML | exit != 0 | **passed** | `migrate-malformed.txt` |  |
| M05 | P1 | migrate config read-only file | migrate/config | chmod 444 current v1 | already-current should still succeed without write; or fail closed if it tries to write | **passed** | `migrate-readonly.txt` |  |
| M06 | P1 | bare ferrum-edge with FERRUM_MODE=migrate | migrate | docs/migrations.md copy-paste without subcommand | same as `run -m migrate` (exit 0 on current file) | **passed** | `migrate-bare.txt` |  |
| M07 | P0 | migrate config does not disclose secrets | migrate/config | consumer keyauth in file | secret string absent from stdout/stderr | **passed** | `migrate-secret.txt` |  |

Evidence paths are under `artifacts/agent-01/evidence/` unless noted.

## 3. Commands and reusable local fixture instructions

See `artifacts/agent-01/harness/README.md`.

```bash
export CXX=g++ CC=gcc
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
export RUSTFLAGS='-C debuginfo=0 -C strip=debuginfo'
cargo --config 'build.rustc-wrapper=""' build --jobs 1 --bin ferrum-edge
export FERRUM_EDGE_BIN=/workspace/target/debug/ferrum-edge
python3 artifacts/agent-01/harness/run_matrix.py
# if shared backend port 21002 is busy, isolated retry:
python3 artifacts/agent-01/harness/retry_failed.py
python3 artifacts/agent-01/harness/missing_protoc.py
python3 artifacts/agent-01/harness/record_extra_builds.py
```

Fixtures: `artifacts/agent-01/fixtures/minimal-http-tcp.yaml` and `.json`.
Do **not** set `auth_mode: none` (only `single`/`multi`; omit to default `single`).
`GatewayConfig` requires `plugin_configs` (use `[]`).
Bind only `127.0.0.1` on 21000–21099. No public backends.

Copy-paste journey (J01) — loopback only:

```bash
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

`reload --pid 0` is exercised only via `setsid --wait`.

## 4. Passed / failed / blocked / not-tested

| Status | Count | Notes |
|--------|-------|-------|
| **passed** | 83 | All runtime/startup/reload/health/shutdown/migrate/docs copy-paste rows on the real debug binary |
| **failed** | 1 | B01 — compiled `build.rs` with `protoc` hidden panics `NotPresent` with no install hint ([#4361](https://github.com/ferrum-edge/ferrum-edge/issues/4361)) |
| **blocked** | 1 | B02 — release LTO OOM at 15 GiB; no `target/release/ferrum-edge` |
| **not-tested** | listed in §8 | cloud secrets, docker/kind, privileged Ambient UDP |

First-pass harness collisions on shared backend `127.0.0.1:21002` produced 502s for P01/S02/R10–R13 and an outdated OpenAPI `path:` key for D06. Isolated-port retry + `path_template`/`path_regex` fixture: all seven passed. Those were **harness** defects, not product bugs.

P0/P1 startup and reload claims were executed against the **real debug binary**, not code-review-only.

## 5. Issue / PR URLs published

| URL | Action |
|-----|--------|
| https://github.com/ferrum-edge/ferrum-edge/issues/4033 | Re-verify HOLD — `docs/tcp_udp_proxy.md` has no `enabled:`; wrapped examples validate |
| https://github.com/ferrum-edge/ferrum-edge/issues/4037 | Re-verify HOLD — file-mode admits hand-authored `openapi_validator` without `api_spec_id`; docs distinguish Admin vs file |
| https://github.com/ferrum-edge/ferrum-edge/issues/4038 | Re-verify HOLD — validate accepts `proxy_id` only; docs now say association is required |
| https://github.com/ferrum-edge/ferrum-edge/issues/4079 | Re-verify HOLD — `reload --pid 0` clap-rejects (`0 is not in 1..=4294967295`), exit 2, no process-group SIGHUP |
| https://github.com/ferrum-edge/ferrum-edge/pull/4066 | Merged docs fix; holds on this SHA |
| https://github.com/ferrum-edge/ferrum-edge/pull/4084 | Merged PID-0 reject; holds on this SHA |
| https://github.com/ferrum-edge/ferrum-edge/issues/4361 | **Opened** — missing-protoc `build.rs` panics `NotPresent` (B01 failed) |
| https://github.com/ferrum-edge/ferrum-edge/pull/4078 | Historical Aug 20 report (closed) |
| https://github.com/ferrum-edge/ferrum-edge/pull/4260 | Incomplete Aug 28 draft (closed; **not updated**) |

No production Rust was changed. Comments with this SHA were posted on #4033, #4037, #4038, and #4079.

## 6. Confirmed RCAs and unresolved hypotheses

### Confirmed (this SHA)

1. **#4033 HOLD.** `docs/tcp_udp_proxy.md` no longer ships `enabled: true`. Prose states stream proxies have no `enabled` field. Wrapped File Mode examples validate (4 proxies). D03/D04 passed.
2. **#4037 HOLD.** File-mode validate admits a proxy-scoped `openapi_validator` with hand-authored `operations` (`path_template` + required `path_regex`) and no `api_spec_id`. Docs L305 distinguish Admin vs file mode.
3. **#4038 HOLD.** File-mode validate accepts `scope: proxy` + `proxy_id` without `proxies[].plugins`. Docs Scope prose now says `proxy_id` alone does not attach.
4. **#4079 HOLD.** Isolated `setsid --wait ferrum-edge reload --pid 0` exits 2 with clap `invalid value '0' for '--pid <PID>': 0 is not in 1..=4294967295`. Harness process was not SIGHUP'd. `unix_reload_pid_t` still refuses `pid == 0` if a value ever reached `kill`.
5. **Config migration chain is empty.** `CURRENT_CONFIG_VERSION` is `"1"`. `migrate config` on a current file is a no-op (exit 0). Missing version / malformed files fail closed. Secrets are not printed (M07).
6. **No PID file.** Reload is `--pid` or `pgrep -x ferrum-edge`.
7. **Precedence** — CLI `-m file` + `-c spec` beat env `FERRUM_MODE=database` and conf ports 21050/21051; logs show `environment variable overrides ferrum.conf`. HTTP 200 on env ports after isolated retry.
8. **Invalid SIGHUP** — last-good routes stay live (`/echo` and `/v2` 200); authenticated `/health` returns `status: degraded` and `config_rejected: true`.
9. **Port 0** disables proxy/admin plaintext listeners and is excluded from reserved-port conflict checks. CP `127.0.0.1:0` does not reserve a stream port.
10. **Missing-protoc (B01) failed — #4361.** A cold/warm `cargo build --bin ferrum-edge` with `protoc` hidden timed out at 180s while still compiling crates (`TIMEOUT` / exit 124) and never reached `prost-build`. Invoking this SHA's compiled `build.rs` (`target/debug/build/ferrum-edge-*/build-script-build`) with `protoc` hidden exits 101:

    ```text
    thread 'main' panicked at tonic-prost-build-0.14.6/src/lib.rs:752:52:
    called `Result::unwrap()` on an `Err` value: NotPresent
    ```

    No `protoc` / `protobuf-compiler` / `PROTOC` install text. The main debug binary was preserved. Aug 20 B01 on `f4b62fe7` recorded an actionable prost-build diagnostic; that quality did not hold.

### Unresolved / out of scope

- Release-profile binary not produced (B02): 15 GiB RAM exhausted during LTO of `ferrum_edge`. Charter forbids extra compiles after OOM.
- Privileged Ambient UDP preflight against a real host `/proc` (help only).
- `auth_mode: none` is invalid (`single`/`multi` only). Not a product bug; easy fixture footgun.
- `GatewayConfig.plugin_configs` is required (no `#[serde(default)]`). Doc fragments that omit it fail before the intended field error.
- First-pass 502s on P01/S02/R10–R13 were leftover `127.0.0.1:21002` backend binds, not listener/reload defects.

## 7. Documentation / example discrepancies

| Document | Discrepancy | Launch impact |
|----------|-------------|---------------|
| `docs/tcp_udp_proxy.md` | **Fixed on this SHA** (no `enabled: true`; prose explains omission) | #4033 hold |
| `docs/openapi_validator.md` L305 | **Fixed** — Admin requires `api_spec_id`; file mode does not | #4037 hold |
| `docs/plugins.md` Scope | **Fixed** — `proxy_id` alone does not attach | #4038 hold |
| `docs/cli.md` | “A subcommand is required” | Bare `ferrum-edge` enters the serving path; without mode it errors `Invalid FERRUM_MODE ''` (C14). `docs/migrations.md` documents the bare binary with `FERRUM_MODE=migrate` (M06 works). |
| `docs/cli.md` subcommand table | No `migrate` subcommand | Correct vs clap (`unrecognized subcommand 'migrate'`); easy to miss that migrate is a mode. |
| File Mode YAML fragments | Often omit `version` / `plugin_configs` | Incomplete snippets fail validate; mark as partial. Full `docs/configuration.md` and README examples validate. |
| README getting-started | `tests/config.yaml` uses public `httpbin.org` | Validates (D05); **do not** use for loopback launch tests. |
| `docs/functional_testing_file_mode.md` | Plugin example still has `enabled: true` | Valid on `plugin_configs` (not on `Proxy`). Not a #4033 regression. |

## 8. Untested third-party-account-only paths

- `_VAULT` / `_AWS` / `_AZURE` / `_GCP` suffixes (`cloud-secrets` not in default features). Default binary **fails closed** on a non-empty cloud suffix (documented).
- Docker / GHCR / kind / kubectl (tools missing).
- Privileged Ambient UDP preflight against a real node / host `/proc` (help only).
- Database/CP/DP live modes (charter is file-mode/CLI/build).
- Windows non-Unix `reload` path (source returns a fixed error; this host is Linux).

## 9. Confidence and verdict

**Confidence: high** on file-mode startup, validation, precedence, port-0, health (plain + TLS), SIGHUP atomicity, SIGTERM/SIGINT rebind, and migrate-config. All of those ran on the real debug binary at `b96cfaadd41a676d39a409d47b48e0b0588fa86e`.

**Verdict: Ready with explicit risks**

- Runtime file-mode HTTP + TCP, validate, reload fail-closed, health gating, and shutdown/rebind worked on loopback.
- The Aug 20 product/docs failures (#4033 `enabled: true`, #4079 `reload --pid 0`) **hold as fixed** on this SHA.
- Remaining risks: #4361 (source-build `protoc` panic, no runtime impact), no release binary on this VM (B02 OOM), untested cloud-secret suffixes, container/K8s, and privileged Ambient UDP.

## 10. Three most important follow-ups by launch risk

1. **Smoke a release binary on a machine with enough RAM for LTO (B02).** This 15 GiB VM OOM-killed the release link. Operators should not ship only the 383 MiB debug binary.
2. **Fail closed with an install diagnostic when `protoc` is missing (#4361 / B01).** `build.rs` should preflight `PROTOC`/`protoc` instead of panicking `NotPresent` via tonic-prost-build unwrap. Source-build only; published images already ship `protoc`.
3. **Align CLI docs** (`subcommand required` vs bare `ferrum-edge` + `FERRUM_MODE=migrate`) so migrate-mode copy-paste matches `docs/cli.md`. Low runtime risk; high operator confusion.

---

### Hot-zone re-verify (this SHA vs Aug 20 `f4b62fe7`)

| Issue | Aug 20 `f4b62fe7` | This SHA `b96cfaad` |
|-------|-------------------|---------------------|
| #4033 `enabled: true` in `tcp_udp_proxy.md` | failed validate | **HOLD** — field gone; validate 0 |
| #4037 `api_spec_id` docs | docs claimed universal require | **HOLD** — Admin vs file distinguished; file validate 0 |
| #4038 `proxy_id` vs `plugins[]` | docs implied `proxy_id` sufficient | **HOLD** — docs corrected; validate still admits ID-only |
| #4079 `reload --pid 0` | process-group SIGHUP (exit 129) | **HOLD** — clap range reject, exit 2, no kill |

### What changed vs the Aug 20 `f4b62fe` run

- Same domain, **new SHA** (`b96cfaad`, not `f4b62fe7`).
- Prior 2 failures are **fixed on main** (#4066, #4084) and re-verified with the real binary. Do not reopen #4033 / #4079.
- **83 passed / 1 failed / 1 blocked** vs Aug 20 **83/85 pass**, 2 failed (#4033, #4079), Ready with risks.
- New residual: #4361 missing-protoc `NotPresent` panic (Aug 20 B01 was actionable). Release binary blocked by VM OOM (charter: use debug).
- Incomplete Aug 28 draft PR #4260 was **not** updated; this is a new artifacts tree and a new PR.
