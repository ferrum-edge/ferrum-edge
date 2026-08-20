# Launch-readiness report: build / CLI / configuration / file mode

Domain: Build, CLI, configuration precedence, validation, file mode, reload, and migration.
Agent: Launch-Readiness Agent 01 (execution worker).

## 1. Tested revision and environment

| Item | Value |
|------|-------|
| Tested SHA | `f4b62fe7d4620d81c836d6418f2957269ac6e115` |
| Expected pin | `f4b62fe7d4620d81c836d6418f2957269ac6e115` (match) |
| Working tree at start | clean (detached HEAD, then branch `cursor/launch-readiness-build-cli-config-dde3`) |
| OS / kernel | Linux cursor 6.12.94+ (Ubuntu Noble) |
| Arch | x86_64 |
| CPU | 4× Intel Xeon (KVM) |
| Memory | 15 GiB RAM, 0 swap |
| rustc | 1.97.1 (8bab26f4f 2026-07-14) |
| cargo | 1.97.1 (c980f4866 2026-06-30) |
| protoc | libprotoc 3.21.12 (installed this run; was missing at boot) |
| docker / kind / kubectl | **missing** |
| openssl | OpenSSL 3.0.13 30 Jan 2024 |
| curl | 8.5.0 |
| python | 3.12.3 |
| g++ / gcc | 13.3.0 |
| clang | 18.1.3 |
| mold | 2.30.0 |
| sccache | **missing**; `.cargo/config.toml` sets `build.rustc-wrapper = "sccache"` — builds use `cargo --config 'build.rustc-wrapper=""'` |
| Build profile | debug then release, `--bin ferrum-edge` only, `RUSTFLAGS='-C debuginfo=0'`, `-j 2` then `-j 1` if memory tight |
| Features | default crate features only (`crypto-ring`); no `cloud-secrets` / `fips` / `ebpf` |
| Non-default `FERRUM_*` in parent env at start | **none** |
| Listener policy | all binds `127.0.0.1`, ports **21000–21099** only |

### Prerequisites installed this run

```text
sudo apt-get install -y build-essential g++ libstdc++-13-dev protobuf-compiler \
  libcurl4-openssl-dev libssl-dev cmake pkg-config clang libclang-dev \
  libsasl2-dev zlib1g-dev mold
export CXX=g++ CC=gcc
```

### Binary paths (filled after builds)

| Profile | Path | Status |
|---------|------|--------|
| debug | `/workspace/target/debug/ferrum-edge` | in progress at report draft |
| release | `/workspace/target/release/ferrum-edge` | not started |

## 2. Coverage matrix

See `artifacts/agent-01/evidence/matrix-results.json` for the machine-readable matrix after the harness runs. Human table (ID \| Priority \| Capability \| Mode/Protocol \| Method \| Expected \| Result \| Evidence \| Issue/PR) is appended in section 2b once execution completes.

Target: ≥35 rows including ≥12 negative config, ≥5 reload/atomicity, ≥3 shutdown/restart, and one complete copy-paste journey.

## 3. Commands and reusable local fixture instructions

See `artifacts/agent-01/harness/README.md`.

```bash
export CXX=g++ CC=gcc RUSTFLAGS='-C debuginfo=0'
cargo --config 'build.rustc-wrapper=""' build --bin ferrum-edge -j 1
export FERRUM_EDGE_BIN=/workspace/target/debug/ferrum-edge
python3 artifacts/agent-01/harness/run_matrix.py
```

Fixtures: `artifacts/agent-01/fixtures/minimal-http-tcp.yaml` and `.json`.
The harness rewrites ports to 21000–21099 and starts loopback HTTP/TCP echo backends.

## 4. Passed / failed / blocked / not-tested

Draft: harness not yet executed against a finished binary. Build in progress.

| Status | Count | Notes |
|--------|-------|-------|
| passed | 0 | |
| failed | 0 | |
| blocked | 0 | |
| not-tested | pending | release binary, missing-protoc rebuild, PR #4066 worktree, docker/kind paths |

## 5. Issue / PR URLs published

None yet from this worker (comments/issues will be added after binary evidence).

Known related (not created by this run):

- https://github.com/ferrum-edge/ferrum-edge/issues/4033
- https://github.com/ferrum-edge/ferrum-edge/issues/4037
- https://github.com/ferrum-edge/ferrum-edge/issues/4038
- https://github.com/ferrum-edge/ferrum-edge/pull/4066 (docs-only, **not merged**, base = this SHA)

## 6. Confirmed RCAs and unresolved hypotheses

Pending binary execution. Working hypotheses from source/docs inventory:

- #4033: `Proxy` has `#[serde(deny_unknown_fields)]` and no `enabled` field; `docs/tcp_udp_proxy.md` still documents `enabled: true`.
- #4037: `api_spec_id` precondition is Admin API only; file-mode hand-authored `operations` validate.
- #4038: `PluginCache` attaches via `proxies[].plugins`; `proxy_id` is consistency, not attachment.
- `migrate` is an operating mode (`FERRUM_MODE=migrate`), not a clap subcommand. `docs/cli.md` says a subcommand is required; `docs/migrations.md` invokes the bare binary.
- No PID-file implementation exists (`reload --pid` or `pgrep` only).
- Config migration chain is empty; current version is `"1"` — `migrate config` is a no-op on current files (backup only when a step applies).

## 7. Documentation / example discrepancies

Inventory (to be confirmed with `validate`):

- `docs/tcp_udp_proxy.md` File Mode YAML includes `enabled: true` (#4033; PR #4066 unmerged).
- `docs/configuration.md` stream examples do **not** use `enabled` (already correct).
- `docs/openapi_validator.md` L305 vs file-mode experiments (#4037).
- `docs/plugins.md` Scope prose vs `proxies[].plugins` (#4038).
- `docs/cli.md` “subcommand is required” vs bare `ferrum-edge` migrate path.
- README getting-started uses `tests/config.yaml` (public backends — not used for live traffic here).

## 8. Untested third-party-account-only paths

- Vault / AWS / Azure / GCP secret suffixes (`cloud-secrets` not in default features).
- Paid SaaS, public HTTPBin, Docker Hub / GHCR pulls, Kubernetes (no docker/kind/kubectl).
- Ambient UDP preflight against a real node / host `/proc` (help only; no privileged node).

## 9. Confidence and verdict

**Verdict (draft): Not ready to score** — binary execution not finished.

Final verdict will be one of: Ready | Ready with explicit risks | Not ready.

## 10. Three most important follow-ups by launch risk

1. Finish debug+release builds and execute every P0/P1 harness row on this SHA.
2. Re-verify #4033/#4037/#4038 on the real binary; comment with evidence; do not treat #4066 as merged.
3. Publish issues only for distinct new root causes after search.

---

## 2b. Coverage matrix (human)

*Populated after `run_matrix.py` completes.*
