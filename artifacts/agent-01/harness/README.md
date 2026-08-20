# Agent 01 local harness

Reusable loopback-only fixtures and runner for build/CLI/config/file-mode launch-readiness.

## Preconditions

- Isolated checkout at the recorded SHA
- `protoc` on PATH (or document the missing-protoc diagnostic)
- Binary: `target/debug/ferrum-edge` then `target/release/ferrum-edge`
- Bind **only** `127.0.0.1` on ports **21000–21099**
- No public backends, no real credentials

## Build

```bash
export CXX=g++ CC=gcc
export RUSTFLAGS='-C debuginfo=0'
# sccache is configured in .cargo/config.toml but may be missing
cargo --config 'build.rustc-wrapper=""' build --bin ferrum-edge -j 1
cargo --config 'build.rustc-wrapper=""' build --release --bin ferrum-edge -j 1
```

## Run the matrix

```bash
export FERRUM_EDGE_BIN=/workspace/target/debug/ferrum-edge
python3 artifacts/agent-01/harness/run_matrix.py
```

Evidence lands under `artifacts/agent-01/evidence/`.
