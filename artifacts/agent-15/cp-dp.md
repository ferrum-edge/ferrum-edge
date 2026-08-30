# Launch-readiness report: CP/DP distribution

Domain: Control-plane / data-plane distribution, config push, last-good, exclusive `FERRUM_MODE`.
Agent: Launch-Readiness Agent 15. **Investigation only** — artifacts only, no production Rust.

**Status:** harness staged; live matrix not yet executed. This file will be replaced after the loopback CP+DP run on the debug binary.

## 1. Tested revision and environment

| Item | Value |
|------|-------|
| **Product SHA tested** | `bf05855f8429e466511610f9072f666b45cd309a` |
| `origin/main` at start | `bf05855f8429e466511610f9072f666b45cd309a` (match; fetched 2026-08-30) |
| Listeners | **127.0.0.1 only**, ports **22400–22499**, prefix `fe-agent-15-` |
| Build | Agent 11 light: `cargo --config 'build.rustc-wrapper=""' build --jobs 1 --bin ferrum-edge` + `RUSTFLAGS='-C debuginfo=0 -C strip=debuginfo'` |

## Charter

- exclusive `FERRUM_MODE`
- DP last-good slices
- invalid first slice watermark (#4041 CLOSED — HOLD re-verify `record_rejected_slice`; do not duplicate)
- `REGISTRY_ONLY`
- gateway-to-mesh via `provider: mesh`
- CP is a config broker, not a proxy
- Local CP+DP processes, loopback only

## 2. Coverage matrix

See `artifacts/agent-15/evidence/matrix-results.json` after the harness run.
