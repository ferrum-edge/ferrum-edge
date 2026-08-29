# Agent 01 local harness

Reusable loopback-only fixtures and runner for build/CLI/config/file-mode
launch-readiness on **current origin/main**.

This is a **new artifacts tree** (do not confuse with closed draft PRs #4078 / #4260).

## Preconditions

- Isolated checkout at the recorded SHA
- `protoc` on PATH (or document the missing-protoc diagnostic)
- Binary: `target/debug/ferrum-edge` then `target/release/ferrum-edge`
- Bind **only** `127.0.0.1` on ports **21000–21099**
- No public backends, no real credentials

## Build

```bash
export CXX=g++ CC=gcc
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
export RUSTFLAGS='-C debuginfo=0 -C strip=debuginfo'
# sccache is configured in .cargo/config.toml but may be missing
cargo --config 'build.rustc-wrapper=""' build --jobs 1 --bin ferrum-edge
cargo --config 'build.rustc-wrapper=""' build --jobs 1 --release --bin ferrum-edge
```

Missing-protoc diagnostic (separate target dir so the main binary is not overwritten):

```bash
python3 artifacts/agent-01/harness/missing_protoc.py
```

## Run the matrix

```bash
export FERRUM_EDGE_BIN=/workspace/target/debug/ferrum-edge
python3 artifacts/agent-01/harness/run_matrix.py
python3 artifacts/agent-01/harness/record_extra_builds.py
```

`reload --pid 0` is exercised only via `setsid --wait` (safe if #4079 regresses).

Evidence lands under `artifacts/agent-01/evidence/`.
Do **not** set `auth_mode: none` (only `single`/`multi`; omit to default `single`).
`GatewayConfig` requires `plugin_configs` (use `[]`).
