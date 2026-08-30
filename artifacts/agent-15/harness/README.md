# Agent 15 CP/DP launch-readiness harness

Loopback-only. Ports `127.0.0.1:22400–22499`. Prefix `fe-agent-15-`.

## Compile (Agent 11 light)

```bash
export CXX=g++ CC=gcc
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
export RUSTFLAGS='-C debuginfo=0 -C strip=debuginfo'
cargo --config 'build.rustc-wrapper=""' build --jobs 1 --bin ferrum-edge
export FERRUM_EDGE_BIN=/workspace/target/debug/ferrum-edge
```

## Run

```bash
python3 artifacts/agent-15/harness/run_matrix.py
```

Workdir: `/tmp/fe-agent-15/` (logs, sqlite, evidence copies).
Sanitized evidence is written to `artifacts/agent-15/evidence/`.

Do **not** set `auth_mode: none`. Bind only `127.0.0.1`. CP is a config broker (no proxy).
